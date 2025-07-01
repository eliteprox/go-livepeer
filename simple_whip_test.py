#!/usr/bin/env python3
"""
Simple WHIP-ingest job test script (no crypto signing required)

This is a simplified version for testing WHIP job submission without
proper cryptographic signing. Use this for basic testing when you don't
have a proper Ethereum private key setup.

Requirements:
    pip install requests
"""

import json
import base64
import requests
import uuid
import time

# Configuration
GATEWAY_URL = "http://localhost:8937"  # Default gateway URL
ENDPOINT = "/process/request/whip-ingest"

def generate_mock_sdp_offer():
    """Generate a mock SDP offer for WHIP testing"""
    session_id = str(int(time.time()))
    session_version = "2"
    
    sdp_offer = f"""v=0
o=- {session_id} {session_version} IN IP4 0.0.0.0
s=-
t=0 0
a=group:BUNDLE 0
a=extmap-allow-mixed
a=msid-semantic: WMS stream
m=video 9 UDP/TLS/RTP/SAVPF 96 97 98 99 100 101 127 125 124
c=IN IP4 0.0.0.0
a=rtcp:9 IN IP4 0.0.0.0
a=ice-ufrag:4ZcD
a=ice-pwd:2/1muCWoOi3uHTiC4c6RUKAs
a=ice-options:trickle
a=fingerprint:sha-256 19:E2:1C:3B:4B:9F:81:E6:B8:5C:F4:A5:A8:D8:73:04:BB:05:2F:70:9F:04:A9:0E:05:E9:26:33:E8:70:88:A2
a=setup:actpass
a=mid:0
a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level
a=extmap:2 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time
a=extmap:3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01
a=extmap:4 urn:ietf:params:rtp-hdrext:sdes:mid
a=extmap:5 urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id
a=extmap:6 urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id
a=sendonly
a=msid:stream video
a=rtcp-mux
a=rtcp-rsize
a=rtpmap:96 VP8/90000
a=rtcp-fb:96 goog-remb
a=rtcp-fb:96 transport-cc
a=rtcp-fb:96 ccm fir
a=rtcp-fb:96 nack
a=rtcp-fb:96 nack pli
a=rtpmap:97 rtx/90000
a=fmtp:97 apt=96
a=rtpmap:98 VP9/90000
a=rtcp-fb:98 goog-remb
a=rtcp-fb:98 transport-cc
a=rtcp-fb:98 ccm fir
a=rtcp-fb:98 nack
a=rtcp-fb:98 nack pli
a=rtpmap:99 rtx/90000
a=fmtp:99 apt=98
a=rtpmap:100 H264/90000
a=rtcp-fb:100 goog-remb
a=rtcp-fb:100 transport-cc
a=rtcp-fb:100 ccm fir
a=rtcp-fb:100 nack
a=rtcp-fb:100 nack pli
a=fmtp:100 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f
a=rtpmap:101 rtx/90000
a=fmtp:101 apt=100
a=rtpmap:127 red/90000
a=rtpmap:125 rtx/90000
a=fmtp:125 apt=127
a=rtpmap:124 ulpfec/90000
a=ssrc-group:FID 1234567890 1234567891
a=ssrc:1234567890 cname:test-stream
a=ssrc:1234567890 msid:stream video
a=ssrc:1234567891 cname:test-stream
a=ssrc:1234567891 msid:stream video
"""
    return sdp_offer.strip()

def create_mock_job_request(stream_id, timeout_seconds=120):
    """Create a mock JobRequest structure for WHIP-ingest (no real signing)"""
    
    # Generate unique job ID
    job_id = f"whip-job-{uuid.uuid4().hex[:8]}"
    
    # Create job request details
    job_request_details = {
        "start_stream": True,
        "stream_id": stream_id
    }
    
    # Create mock job request with fake signature
    job_request = {
        "id": job_id,
        "request": json.dumps(job_request_details),
        "parameters": "{}",
        "capability": "whip-ingest",
        "timeout_seconds": timeout_seconds
    }
    
    return job_request

def send_whip_job_request(gateway_url, job_request, sdp_offer, request_format="raw_sdp"):
    """Send a WHIP-ingest job request to the gateway"""
    
    # Create the full URL
    url = f"{gateway_url}{ENDPOINT}"
    
    # Encode job request as base64
    job_request_json = json.dumps(job_request)
    job_request_b64 = base64.b64encode(job_request_json.encode('utf-8')).decode('utf-8')
    
    # Prepare headers
    headers = {
        "Livepeer": job_request_b64,
        "Livepeer-Orch-Search-Timeout": "2s",
        "Livepeer-Orch-Search-Resp-Timeout": "1s"
    }
    
    # Prepare request body based on format
    if request_format == "raw_sdp":
        headers["Content-Type"] = "application/sdp"
        body = sdp_offer
    else:  # JSON format
        headers["Content-Type"] = "application/json"
        body = json.dumps({"sdp_offer": sdp_offer})
    
    print(f"🚀 Sending WHIP-ingest job request to: {url}")
    print(f"📋 Job ID: {job_request['id']}")
    print(f"🎯 Stream ID: {json.loads(job_request['request'])['stream_id']}")
    print(f"⏱️  Timeout: {job_request['timeout_seconds']} seconds")
    print(f"📄 Request format: {request_format}")
    print(f"🔗 Full URL: {url}")
    print()
    
    print("📋 Request Headers:")
    for key, value in headers.items():
        if key == "Livepeer":
            print(f"   {key}: {value[:50]}... (base64 encoded job request)")
        else:
            print(f"   {key}: {value}")
    print()
    
    print("📄 Request Body Preview:")
    if request_format == "raw_sdp":
        print("   [Raw SDP]")
        print("   " + "\n   ".join(body.split('\n')[:5]))
        print("   ... (truncated)")
    else:
        print("   [JSON with SDP]")
        print(f"   {json.dumps(json.loads(body), indent=2)[:200]}...")
    print()
    
    try:
        # Send the request
        response = requests.post(url, headers=headers, data=body, timeout=30)
        
        print(f"📊 Response Status: {response.status_code}")
        print(f"📋 Response Headers:")
        for key, value in response.headers.items():
            if key.lower().startswith('livepeer') or key.lower() in ['content-type', 'location']:
                print(f"   {key}: {value}")
        
        print(f"\n📄 Response Body:")
        if response.headers.get('content-type', '').startswith('application/sdp'):
            print("   [SDP Answer]")
            print("   " + "\n   ".join(response.text.split('\n')[:10]))
            if len(response.text.split('\n')) > 10:
                print("   ... (truncated)")
        else:
            try:
                response_json = response.json()
                print(f"   {json.dumps(response_json, indent=2)}")
            except:
                print(f"   {response.text}")
        
        return response
        
    except requests.exceptions.ConnectionError:
        print(f"❌ Connection failed. Is the gateway running at {gateway_url}?")
        return None
    except requests.exceptions.RequestException as e:
        print(f"❌ Request failed: {e}")
        return None

def test_gateway_connectivity(gateway_url):
    """Test basic connectivity to the gateway"""
    try:
        # Try a simple GET request to see if gateway is responding
        response = requests.get(f"{gateway_url}/status", timeout=5)
        print(f"✅ Gateway is reachable (status: {response.status_code})")
        return True
    except requests.exceptions.RequestException:
        try:
            # Try the root path
            response = requests.get(gateway_url, timeout=5)
            print(f"✅ Gateway is reachable at root (status: {response.status_code})")
            return True
        except requests.exceptions.RequestException:
            print(f"❌ Gateway is not reachable at {gateway_url}")
            return False

def main():
    """Main function to run the test"""
    print("🎬 Simple Livepeer WHIP-ingest Job Test")
    print("=" * 50)
    print("⚠️  Note: This uses mock signatures for testing purposes")
    print("   Real gateway will likely reject these requests due to invalid signatures")
    print()
    
    # Test gateway connectivity first
    if not test_gateway_connectivity(GATEWAY_URL):
        print("\n💡 Tips:")
        print("   - Make sure the Livepeer Gateway is running")
        print("   - Check if the URL is correct")
        print("   - Try changing GATEWAY_URL in the script")
        return
    
    # Generate test data
    stream_id = f"test-stream-{int(time.time())}"
    sdp_offer = generate_mock_sdp_offer()
    
    # Create mock job request
    job_request = create_mock_job_request(stream_id)
    
    print(f"✅ Generated mock job request:")
    print(f"   Job ID: {job_request['id']}")
    print(f"   Stream ID: {stream_id}")
    print()
    
    # Test both request formats
    for request_format in ["raw_sdp", "json"]:
        print(f"🧪 Testing {request_format.upper()} format...")
        print("-" * 40)
        
        response = send_whip_job_request(GATEWAY_URL, job_request, sdp_offer, request_format)
        
        if response:
            if response.status_code == 201:
                print("✅ Success! WHIP session created")
            elif response.status_code == 503:
                print("⚠️  No orchestrators available for whip-ingest capability")
            elif response.status_code == 400:
                print("❌ Bad request - likely due to mock signature or invalid format")
            elif response.status_code == 403:
                print("❌ Forbidden - signature validation failed (expected with mock signature)")
            else:
                print(f"❌ Request failed with status {response.status_code}")
        else:
            print("❌ Request failed - no response")
        
        print("-" * 40)
        print()

if __name__ == "__main__":
    main() 