package monitor

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/golang/glog"
	"github.com/google/uuid"
	"github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/sasl"
	"github.com/segmentio/kafka-go/sasl/plain"
	"github.com/segmentio/kafka-go/sasl/scram"
)

const (
	KafkaBatchInterval        = 1 * time.Second
	KafkaRequestTimeout       = 60 * time.Second
	KafkaBatchSize            = 100
	KafkaDialTimeout          = 10 * time.Second
	KafkaMaxAttempts          = 3
	KafkaShutdownDrainTimeout = 30 * time.Second
	// DefaultKafkaChannelSize is the fallback buffer size used when a non-positive
	// value is passed to InitKafkaProducer.
	DefaultKafkaChannelSize = 10000
)

type KafkaProducer struct {
	writer         *kafka.Writer
	transport      *kafka.Transport
	topic          string
	events         chan GatewayEvent
	gatewayAddress string
	ctx            context.Context
	cancel         context.CancelFunc
	wg             sync.WaitGroup
	closed         atomic.Bool
}

type GatewayEvent struct {
	ID        *string     `json:"id,omitempty"`
	Type      *string     `json:"type"`
	Timestamp *string     `json:"timestamp"`
	Gateway   *string     `json:"gateway,omitempty"`
	Data      interface{} `json:"data"`
}

type PipelineStatus struct {
	Pipeline             string      `json:"pipeline"`
	StartTime            float64     `json:"start_time"`
	LastParamsUpdateTime float64     `json:"last_params_update_time"`
	LastParams           interface{} `json:"last_params"`
	LastParamsHash       string      `json:"last_params_hash"`
	InputFPS             float64     `json:"input_fps"`
	OutputFPS            float64     `json:"output_fps"`
	LastInputTime        float64     `json:"last_input_time"`
	LastOutputTime       float64     `json:"last_output_time"`
	RestartCount         int         `json:"restart_count"`
	LastRestartTime      float64     `json:"last_restart_time"`
	LastRestartLogs      []string    `json:"last_restart_logs"`
	LastError            *string     `json:"last_error"`
	StreamID             *string     `json:"stream_id"`
}

var kafkaProducer *KafkaProducer

func InitKafkaProducer(bootstrapServers, user, password, topic, gatewayAddress, saslMechanism string, channelSize int) error {
	producer, err := newKafkaProducer(bootstrapServers, user, password, topic, gatewayAddress, saslMechanism, channelSize)
	if err != nil {
		return err
	}
	kafkaProducer = producer
	producer.wg.Add(1)
	go producer.drain()
	return nil
}

// ShutdownKafkaProducer stops the drain goroutine, flushes the underlying Kafka
// writer, and waits for in-flight writes to complete. Safe to call when no
// producer was initialized.
func ShutdownKafkaProducer(ctx context.Context) {
	p := kafkaProducer
	if p == nil {
		return
	}
	p.shutdown(ctx)
}

func newKafkaProducer(bootstrapServers, user, password, topic, gatewayAddress, saslMechanism string, channelSize int) (*KafkaProducer, error) {
	if channelSize <= 0 {
		channelSize = DefaultKafkaChannelSize
	}

	transport := &kafka.Transport{
		Dial: (&net.Dialer{
			Timeout:   KafkaDialTimeout,
			DualStack: true,
		}).DialContext,
		DialTimeout: KafkaDialTimeout,
	}

	if user != "" && password != "" {
		var mechanism sasl.Mechanism
		switch saslMechanism {
		case "scram-sha-256":
			m, err := scram.Mechanism(scram.SHA256, user, password)
			if err != nil {
				return nil, fmt.Errorf("failed to create SCRAM-SHA-256 mechanism: %w", err)
			}
			mechanism = m
		case "scram-sha-512":
			m, err := scram.Mechanism(scram.SHA512, user, password)
			if err != nil {
				return nil, fmt.Errorf("failed to create SCRAM-SHA-512 mechanism: %w", err)
			}
			mechanism = m
		default:
			mechanism = &plain.Mechanism{Username: user, Password: password}
		}
		transport.SASL = mechanism
		transport.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
	}

	ctx, cancel := context.WithCancel(context.Background())
	p := &KafkaProducer{
		topic:          topic,
		events:         make(chan GatewayEvent, channelSize),
		gatewayAddress: gatewayAddress,
		transport:      transport,
		ctx:            ctx,
		cancel:         cancel,
	}

	p.writer = &kafka.Writer{
		Addr:         kafka.TCP(bootstrapServers),
		Topic:        topic,
		Balancer:     kafka.CRC32Balancer{},
		Transport:    transport,
		Async:        true,
		BatchSize:    KafkaBatchSize,
		BatchTimeout: KafkaBatchInterval,
		WriteTimeout: KafkaRequestTimeout,
		MaxAttempts:  KafkaMaxAttempts,
		Completion: func(messages []kafka.Message, err error) {
			if err == nil {
				return
			}
			glog.Errorf("kafka async write failed, count=%d, topic=%s, err=%v", len(messages), topic, err)
			KafkaWriteError(len(messages))
		},
	}

	glog.Infof("kafka producer initialized: topic=%s channelSize=%d batchSize=%d batchTimeout=%s",
		topic, channelSize, KafkaBatchSize, KafkaBatchInterval)

	return p, nil
}

// drain reads events from the buffered channel and hands them to the async
// kafka writer. WriteMessages returns immediately because the writer is in
// async mode, so this goroutine never blocks on broker latency.
func (p *KafkaProducer) drain() {
	defer p.wg.Done()
	for {
		select {
		case <-p.ctx.Done():
			p.drainRemaining()
			return
		case event := <-p.events:
			p.write(event)
		}
	}
}

func (p *KafkaProducer) drainRemaining() {
	for {
		select {
		case event := <-p.events:
			p.write(event)
		default:
			return
		}
	}
}

func (p *KafkaProducer) write(event GatewayEvent) {
	value, err := json.Marshal(event)
	if err != nil {
		glog.Errorf("error while marshalling gateway log to Kafka, err=%v", err)
		return
	}
	msg := kafka.Message{
		Key:   []byte(*event.ID),
		Value: value,
	}
	if err := p.writer.WriteMessages(context.Background(), msg); err != nil {
		// In Async mode this only fires for synchronous validation errors
		// (e.g. closed writer); transport/broker errors go to Completion.
		glog.Warningf("kafka enqueue failed, topic=%s, err=%v", p.topic, err)
		KafkaWriteError(1)
	}
}

func (p *KafkaProducer) shutdown(ctx context.Context) {
	if !p.closed.CompareAndSwap(false, true) {
		return
	}

	p.cancel()

	doneCh := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(doneCh)
	}()

	timeout := KafkaShutdownDrainTimeout
	select {
	case <-doneCh:
	case <-ctx.Done():
		glog.Warningf("kafka producer shutdown: parent context cancelled before drain finished")
	case <-time.After(timeout):
		glog.Warningf("kafka producer shutdown: drain did not complete within %s", timeout)
	}

	if err := p.writer.Close(); err != nil {
		glog.Errorf("kafka producer shutdown: writer close error: %v", err)
	}
	if p.transport != nil {
		p.transport.CloseIdleConnections()
	}
	glog.Infof("kafka producer shutdown complete")
}

func SendQueueEventAsync(eventType string, data interface{}) {
	p := kafkaProducer
	if p == nil || p.closed.Load() {
		return
	}

	randomID := uuid.New().String()
	timestampMs := time.Now().UnixMilli()

	event := GatewayEvent{
		ID:        stringPtr(randomID),
		Gateway:   stringPtr(p.gatewayAddress),
		Type:      &eventType,
		Timestamp: stringPtr(fmt.Sprint(timestampMs)),
		Data:      data,
	}

	select {
	case p.events <- event:
	default:
		glog.Warningf("kafka producer event queue is full, dropping event %q", eventType)
		KafkaEventSendError(eventType)
	}
}

func stringPtr(s string) *string {
	return &s
}
