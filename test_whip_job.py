#!/usr/bin/env python3
"""
Test script for sending WHIP-ingest job requests to Livepeer Gateway

This script demonstrates how to:
1. Generate a mock SDP offer for WHIP
2. Create the proper JobRequest structure
3. Send the request to the gateway endpoint

Requirements:
    pip install requests eth-account eth-hash
"""

import json
import base64
import requests
import uuid
import time
from datetime import datetime
from eth_account import Account
from eth_account.messages import encode_defunct
from Crypto.Hash import keccak

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

def create_job_request(stream_id, timeout_seconds=120):
    """Create a JobRequest structure for WHIP-ingest"""
    
    # Generate unique job ID
    job_id = f"whip-job-{uuid.uuid4().hex[:8]}"
    
    # Create job request details
    job_request_details = {
        "start_stream": True,
        "stream_id": stream_id
    }
    
    # Create the main job request
    job_request = {
        "id": job_id,
        "request": json.dumps(job_request_details),
        "parameters": "{}",
        "capability": "whip-ingest",
        # "capability_url": "",  # Will be set by orchestrator
        # "sender": "",  # Will be set after signing
        # "sig": "",  # Will be set after signing
        "timeout_seconds": timeout_seconds
    }
    
    return job_request

def sign_job_request(job_request, private_key):
    """Sign a job request with the given private key"""
    
    # Create account from private key
    account = Account.from_key(private_key)
    
    # Set the sender address
    job_request["sender"] = account.address
    
    # Create message to sign (request + parameters)
    message_to_sign = job_request["request"] + job_request["parameters"]
    
    # Hash the message with Keccak256 (same as in Go code: crypto.Keccak256(msg))
    message_bytes = message_to_sign.encode('utf-8')
    keccak_hash = keccak.new(digest_bits=256)
    keccak_hash.update(message_bytes)
    message_hash = keccak_hash.digest()
    
    # Create signable message (the Go code signs the hash directly)
    signable_message = encode_defunct(message_hash)
    
    # Sign the message
    signature = account.sign_message(signable_message)
    
    # Set the signature (with 0x prefix)
    job_request["sig"] = "0x" + signature.signature.hex()
    
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
    print(f"👤 Sender: {job_request['sender']}")
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
            print("   " + "\n   ".join(response.text.split('\n')[:10]))  # Show first 10 lines
            if len(response.text.split('\n')) > 10:
                print("   ... (truncated)")
        else:
            try:
                response_json = response.json()
                print(f"   {json.dumps(response_json, indent=2)}")
            except:
                print(f"   {response.text}")
        
        return response
        
    except requests.exceptions.RequestException as e:
        print(f"❌ Request failed: {e}")
        return None

def main():
    """Main function to run the test"""
    print("🎬 Livepeer WHIP-ingest Job Test")
    print("=" * 50)
    
    # Generate test data
    stream_id = f"test-stream-{int(time.time())}"
    sdp_offer = generate_mock_sdp_offer()
    
    # Create job request
    job_request = create_job_request(stream_id)
    
    # For testing, we'll use a random private key
    # In production, you'd use your actual private key
    test_private_key = "0x" + "1" * 64  # Simple test key - DO NOT USE IN PRODUCTION
    
    # Sign the job request
    try:
        signed_job_request = sign_job_request(job_request, test_private_key)
    except Exception as e:
        print(f"❌ Failed to sign job request: {e}")
        return
    
    print(f"✅ Generated job request:")
    print(f"   Job ID: {signed_job_request['id']}")
    print(f"   Stream ID: {stream_id}")
    print(f"   Sender: {signed_job_request['sender']}")
    print(f"   Signature: {signed_job_request['sig'][:20]}...")
    print()
    
    # Test both request formats
    for request_format in ["raw_sdp", "json"]:
        print(f"🧪 Testing {request_format.upper()} format...")
        response = send_whip_job_request(GATEWAY_URL, signed_job_request, sdp_offer, request_format)
        
        if response and response.status_code == 201:
            print("✅ Success! WHIP session created")
        elif response and response.status_code == 503:
            print("⚠️  No orchestrators available for whip-ingest capability")
        elif response and response.status_code == 400:
            print("❌ Bad request - check job request format")
        elif response:
            print(f"❌ Request failed with status {response.status_code}")
        else:
            print("❌ Request failed - no response")
        
        print("-" * 30)
        print()

if __name__ == "__main__":
    main() 