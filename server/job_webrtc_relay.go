package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang/glog"
	"github.com/pion/rtp"
	"github.com/pion/webrtc/v4"
)

// WHIPSession represents a WHIP ingestion session
type WHIPSession struct {
	ID         string
	PeerConn   *webrtc.PeerConnection
	Tracks     map[string]*webrtc.TrackRemote
	mu         sync.RWMutex
	Created    time.Time
	LastUpdate time.Time
}

// WHEPSession represents a WHEP egress session
type WHEPSession struct {
	ID         string
	PeerConn   *webrtc.PeerConnection
	Tracks     map[string]*webrtc.TrackLocalStaticRTP
	mu         sync.RWMutex
	Created    time.Time
	LastUpdate time.Time
}

// RelayServer manages WHIP/WHEP connections and media relay
type RelayServer struct {
	ctx     context.Context
	ingress *WHIPSession
	egress  []*WHEPSession

	mu         sync.RWMutex
	transforms map[string]func([]byte) []byte
	stats      *RelayStats
}

// RelayStats tracks relay statistics
type RelayStats struct {
	PacketsReceived    int64         `json:"packets_received"`
	PacketsTransmitted int64         `json:"packets_transmitted"`
	BytesReceived      int64         `json:"bytes_received"`
	BytesTransmitted   int64         `json:"bytes_transmitted"`
	TransformTime      time.Duration `json:"transform_time"`
	mu                 sync.RWMutex
}

func NewRelayServer(ctx context.Context) (*RelayServer, func([]byte, string, string) (string, int, error)) {
	rs := &RelayServer{
		ingress:    &WHIPSession{},
		egress:     []*WHEPSession{},
		transforms: make(map[string]func([]byte) []byte),
		stats:      &RelayStats{},
	}

	go rs.Start()

	// Add transformations if applicable
	// e.g. time stamp correction, audio/video preprocessing, etc
	//rs.transforms["audio"] = rs.transformAudio
	//rs.transforms["video"] = rs.transformVideo

	return rs, rs.createWHEPSession
}

func (rs *RelayServer) Start() {
	select {
	case <-rs.ctx.Done():
		log.Println("RelayServer: Shutting down")
		rs.cleanupWHIPSession()
		for _, session := range rs.egress {
			session.mu.Lock()
			if session.PeerConn != nil {
				session.PeerConn.Close()
			}
			session.mu.Unlock()
		}
	}
}

// Sample audio transformation (echo effect)
//func (rs *RelayServer) transformAudio(data []byte) []byte {
//	transformed := make([]byte, len(data))
//	copy(transformed, data)
//
//	// Add simple processing (volume adjustment)
//	for i := range transformed {
//		if i < len(data) {
//			transformed[i] = byte(float64(data[i]) * 0.8) // Reduce volume
//		}
//	}
//	return transformed
//}

// Sample video transformation (brightness adjustment)
//func (rs *RelayServer) transformVideo(data []byte) []byte {
//	transformed := make([]byte, len(data))
//	copy(transformed, data)
//
//	// Apply basic brightness adjustment
//	for i := range transformed {
//		if transformed[i] < 255-30 {
//			transformed[i] += 30 // Increase brightness
//		}
//	}
//	return transformed
//}

func (rs *RelayServer) createWHIPSession(body []byte, contentType string, streamID string) (string, string, int, error) {
	// Validate Content-Type
	if contentType != "application/sdp" {
		return "", "", http.StatusBadRequest, errors.New("Content-Type must be application/sdp")
	}

	// Create WebRTC peer connection
	config := webrtc.Configuration{
		ICEServers: []webrtc.ICEServer{
			{URLs: []string{"stun:stun.l.google.com:19302"}},
		},
	}

	peerConn, err := webrtc.NewPeerConnection(config)
	if err != nil {
		return "", "", http.StatusInternalServerError, errors.New(fmt.Sprintf("Failed to create peer connection: %v", err))
	}

	// Generate session ID
	sessionID := streamID

	session := &WHIPSession{
		ID:         sessionID,
		PeerConn:   peerConn,
		Tracks:     make(map[string]*webrtc.TrackRemote),
		Created:    time.Now(),
		LastUpdate: time.Now(),
	}

	// Handle incoming tracks
	peerConn.OnTrack(func(track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {
		log.Printf("WHIP Session %s: Received track %s", sessionID, track.Kind().String())

		session.mu.Lock()
		session.Tracks[track.Kind().String()] = track
		session.mu.Unlock()

		// Start relaying and transforming this track
		go rs.relayAndTransformTrack(sessionID, track, "whip")
	})

	// Handle connection state changes
	peerConn.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		log.Printf("WHIP Session %s: Connection state changed to %s", sessionID, state.String())
		if state == webrtc.PeerConnectionStateClosed || state == webrtc.PeerConnectionStateFailed {
			rs.cleanupWHIPSession()
		}
	})

	// Set remote description (offer)
	offer := webrtc.SessionDescription{
		Type: webrtc.SDPTypeOffer,
		SDP:  string(body),
	}

	err = peerConn.SetRemoteDescription(offer)
	if err != nil {
		return "", "", http.StatusBadRequest, errors.New(fmt.Sprintf("Failed to set remote description: %v", err))
	}

	// Create answer
	answer, err := peerConn.CreateAnswer(nil)
	if err != nil {
		return "", "", http.StatusInternalServerError, errors.New(fmt.Sprintf("Failed to create answer: %v", err))
	}

	// Gather ICE candidates and set local description
	gatherComplete := webrtc.GatheringCompletePromise(peerConn)
	if err = peerConn.SetLocalDescription(answer); err != nil {
		e := fmt.Sprintf("SetLocalDescription failed: %v", err)
		return "", "", http.StatusInternalServerError, errors.New(e)
	}
	// Wait for ICE gathering if you want the full candidate set in the SDP
	<-gatherComplete

	err = peerConn.SetLocalDescription(answer)
	if err != nil {
		return "", "", http.StatusInternalServerError, errors.New(fmt.Sprintf("Failed to set local description: %v", err))
	}

	// Store session
	rs.mu.Lock()
	rs.ingress = session
	rs.mu.Unlock()

	glog.Infof("Created WHIP session: %s", sessionID)

	return sessionID, answer.SDP, http.StatusCreated, nil
}

func (rs *RelayServer) createWHEPSession(body []byte, contentType string, streamID string) (string, int, error) {
	if contentType != "application/sdp" {
		return "", http.StatusBadRequest, errors.New("Content-Type must be application/sdp")
	}

	// Create WebRTC peer connection
	config := webrtc.Configuration{
		ICEServers: []webrtc.ICEServer{
			{URLs: []string{"stun:stun.l.google.com:19302"}},
		},
	}

	peerConn, err := webrtc.NewPeerConnection(config)
	if err != nil {
		return "", http.StatusInternalServerError, errors.New(fmt.Sprintf("Failed to create peer connection: %v", err))
	}

	// Generate session ID
	sessionID := streamID

	session := &WHEPSession{
		ID:         sessionID,
		PeerConn:   peerConn,
		Tracks:     make(map[string]*webrtc.TrackLocalStaticRTP),
		Created:    time.Now(),
		LastUpdate: time.Now(),
	}

	// Create and add tracks for available media
	rs.addTracksToWHEPSession(session)

	// Handle connection state changes
	peerConn.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		log.Printf("WHEP Session %s: Connection state changed to %s", sessionID, state.String())
		if state == webrtc.PeerConnectionStateClosed || state == webrtc.PeerConnectionStateFailed {
			rs.cleanupWHEPSession(sessionID)
		}
	})

	// Set remote description (offer)
	offer := webrtc.SessionDescription{
		Type: webrtc.SDPTypeOffer,
		SDP:  string(body),
	}

	err = peerConn.SetRemoteDescription(offer)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to set remote description: %v", err), http.StatusBadRequest)
		return
	}

	// Create answer
	answer, err := peerConn.CreateAnswer(nil)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to create answer: %v", err), http.StatusInternalServerError)
		return
	}

	err = peerConn.SetLocalDescription(answer)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to set local description: %v", err), http.StatusInternalServerError)
		return
	}

	// Store session
	rs.mu.Lock()
	rs.egress = append(rs.egress, session)
	rs.mu.Unlock()

	// Set response headers
	w.Header().Set("Content-Type", "application/sdp")
	w.Header().Set("Location", fmt.Sprintf("/whep/%s", sessionID))
	w.WriteHeader(http.StatusCreated)

	// Send SDP answer
	w.Write([]byte(answer.SDP))

	log.Printf("Created WHEP session: %s", sessionID)
}

func (rs *RelayServer) addTracksToWHEPSession(session *WHEPSession) {
	// Add video track
	videoTrack, err := webrtc.NewTrackLocalStaticRTP(
		webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeVP8},
		"video",
		"relay-stream",
	)
	if err == nil {
		session.Tracks["video"] = videoTrack
		session.PeerConn.AddTrack(videoTrack)
	}

	// Add audio track
	audioTrack, err := webrtc.NewTrackLocalStaticRTP(
		webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeOpus},
		"audio",
		"relay-stream",
	)
	if err == nil {
		session.Tracks["audio"] = audioTrack
		session.PeerConn.AddTrack(audioTrack)
	}
}

func (rs *RelayServer) updateWHIPSession(w http.ResponseWriter, r *http.Request) {
	// Extract session ID from URL
	//sessionID := strings.TrimPrefix(r.URL.Path, "/whip/")

	rs.mu.RLock()
	defer rs.mu.RUnlock()
	// Handle ICE candidate or other updates
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	contentType := r.Header.Get("Content-Type")

	if contentType == "application/trickle-ice-sdpfrag" {
		// Handle ICE candidate
		candidate := strings.TrimSpace(string(body))
		if candidate != "" {
			err = rs.ingress.PeerConn.AddICECandidate(webrtc.ICECandidateInit{
				Candidate: candidate,
			})
			if err != nil {
				http.Error(w, fmt.Sprintf("Failed to add ICE candidate: %v", err), http.StatusBadRequest)
				return
			}
		}
	}

	rs.ingress.LastUpdate = time.Now()
	w.WriteHeader(http.StatusNoContent)
}

func (rs *RelayServer) updateWHEPSession(w http.ResponseWriter, r *http.Request) {
	// Extract session ID from URL
	sessionID := strings.TrimPrefix(r.URL.Path, "/whep/")

	rs.mu.RLock()
	for _, session := range rs.egress {
		if session.ID == sessionID {
			// Handle ICE candidate or other updates
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "Failed to read request body", http.StatusBadRequest)
				return
			}

			contentType := r.Header.Get("Content-Type")

			if contentType == "application/trickle-ice-sdpfrag" {
				// Handle ICE candidate
				candidate := strings.TrimSpace(string(body))
				if candidate != "" {
					err = session.PeerConn.AddICECandidate(webrtc.ICECandidateInit{
						Candidate: candidate,
					})
					if err != nil {
						http.Error(w, fmt.Sprintf("Failed to add ICE candidate: %v", err), http.StatusBadRequest)
						return
					}
				}
			}

			session.LastUpdate = time.Now()
			w.WriteHeader(http.StatusNoContent)
		}
	}

	rs.mu.RUnlock()
	w.WriteHeader(http.StatusServiceUnavailable)
}

func (rs *RelayServer) deleteWHIPSession(w http.ResponseWriter, r *http.Request) {
	//sessionID := strings.TrimPrefix(r.URL.Path, "/whip/")
	rs.mu.Lock()
	defer rs.mu.Unlock()

	if rs.ingress.PeerConn != nil {
		rs.ingress.PeerConn.Close()
	}

	w.WriteHeader(http.StatusNoContent)
}

func (rs *RelayServer) deleteWHEPSession(w http.ResponseWriter, r *http.Request) {
	sessionID := strings.TrimPrefix(r.URL.Path, "/whep/")
	rs.cleanupWHEPSession(sessionID)
	w.WriteHeader(http.StatusNoContent)
}

func (rs *RelayServer) cleanupWHIPSession() {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	if rs.ingress.PeerConn != nil {
		rs.ingress.PeerConn.Close()
	}

	log.Printf("Cleaned up WHIP session: %s", rs.ingress.ID)
	rs.ingress = &WHIPSession{} // Reset the session

	for i, session := range rs.egress {
		session.mu.Lock()
		if session.PeerConn != nil {
			session.PeerConn.Close()
		}
		session.mu.Unlock()
		log.Printf("Cleaned up WHEP session: %s", session.ID)
		rs.egress[i] = nil // Reset the session
	}
	rs.egress = []*WHEPSession{} // Clear the egress sessions
}

func (rs *RelayServer) cleanupWHEPSession(sessionID string) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	for i, session := range rs.egress {
		if session.ID == sessionID {
			if session.PeerConn != nil {
				session.PeerConn.Close()
			}
			rs.egress = append(rs.egress[:i], rs.egress[i+1:]...)
			log.Printf("Cleaned up WHEP session: %s", sessionID)
			break
		}
	}
}

func (rs *RelayServer) relayAndTransformTrack(sessionID string, track *webrtc.TrackRemote, sessionType string) {
	log.Printf("Starting relay and transform for track %s from %s session %s", track.Kind().String(), sessionType, sessionID)

	trackKind := track.Kind().String()

	// Read and process RTP packets
	for {
		rtp, _, err := track.ReadRTP()
		if err != nil {
			if err == io.EOF {
				log.Printf("Track %s from %s session %s ended", trackKind, sessionType, sessionID)
				return
			}
			log.Printf("Error reading RTP: %v", err)
			continue
		}

		// Transform the payload
		if transform, exists := rs.transforms[trackKind]; exists {
			rtp.Payload = transform(rtp.Payload)
		}

		// Update stats
		rs.stats.mu.Lock()
		rs.stats.PacketsReceived++
		rs.stats.BytesReceived += int64(len(rtp.Payload))
		rs.stats.mu.Unlock()

		// Relay to all WHEP sessions
		rs.relayToWHEPSessions(rtp, trackKind)
	}
}

func (rs *RelayServer) relayToWHEPSessions(rtp *rtp.Packet, trackKind string) {
	rs.mu.RLock()
	sessions := make([]*WHEPSession, 0, len(rs.egress))
	for _, session := range rs.egress {
		sessions = append(sessions, session)
	}
	rs.mu.RUnlock()

	for _, session := range sessions {
		session.mu.RLock()
		if track, exists := session.Tracks[trackKind]; exists {
			err := track.WriteRTP(rtp)
			if err != nil {
				log.Printf("Error writing RTP to WHEP session %s: %v", session.ID, err)
			} else {
				rs.stats.mu.Lock()
				rs.stats.PacketsTransmitted++
				rs.stats.BytesTransmitted += int64(len(rtp.Payload))
				rs.stats.mu.Unlock()
			}
		}
		session.mu.RUnlock()
	}
}

// Health check endpoint
func (rs *RelayServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	rs.mu.RLock()
	whepCount := len(rs.egress)
	rs.mu.RUnlock()

	rs.stats.mu.RLock()
	stats := map[string]interface{}{
		"status":              "healthy",
		"whip_sessions":       1,
		"whep_sessions":       whepCount,
		"packets_received":    rs.stats.PacketsReceived,
		"packets_transmitted": rs.stats.PacketsTransmitted,
		"bytes_received":      rs.stats.BytesReceived,
		"bytes_transmitted":   rs.stats.BytesTransmitted,
	}
	rs.stats.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// Session management endpoint
func (rs *RelayServer) handleSessions(w http.ResponseWriter, r *http.Request) {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	sessions := map[string]interface{}{
		"whip_sessions": make([]map[string]interface{}, 0),
		"whep_sessions": make([]map[string]interface{}, 0),
	}
	// Add WHIP session
	sessions["whip_sessions"] = rs.ingress

	// Add WHEP sessions
	for id, session := range rs.egress {
		sessionInfo := map[string]interface{}{
			"id":          id,
			"created":     session.Created,
			"last_update": session.LastUpdate,
			"tracks":      len(session.Tracks),
		}
		sessions["whep_sessions"] = append(sessions["whep_sessions"].([]map[string]interface{}), sessionInfo)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sessions)
}

// Session cleanup routine
func (rs *RelayServer) startCleanupRoutine() {
	ticker := time.NewTicker(30 * time.Second)
	go func() {
		for range ticker.C {
			rs.cleanupStaleSessions()
		}
	}()
}

func (rs *RelayServer) cleanupStaleSessions() {
	cutoff := time.Now().Add(-5 * time.Minute)

	rs.mu.Lock()
	defer rs.mu.Unlock()

	// Cleanup stale WHIP sessions
	if rs.ingress.LastUpdate.Before(cutoff) {
		log.Printf("Cleaning up stale WHIP session: %s", rs.ingress.ID)
		if rs.ingress.PeerConn != nil {
			rs.ingress.PeerConn.Close()
		}
		rs.ingress = nil
	}

	// Cleanup stale WHEP sessions
	for id, session := range rs.egress {
		if session.LastUpdate.Before(cutoff) {
			log.Printf("Cleaning up stale WHEP session: %s", id)
			if session.PeerConn != nil {
				session.PeerConn.Close()
			}
			session = nil
		}
	}
	rs.egress = []*WHEPSession{}
}
