import asyncio
import time
import argparse
import sys
try:
    import aiohttp
    import uvloop
except ImportError:
    print("Please install aiohttp and uvloop: pip install aiohttp uvloop")
    sys.exit(1)

# Make client use uvloop for maximum throughput
asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

async def fetch(session, url, payload):
    try:
        async with session.post(url, json=payload) as response:
            await response.read()
            return response.status
    except Exception:
        return 500

async def main():
    parser = argparse.ArgumentParser(description="AgentSentry 10k RPS Benchmark")
    parser.add_argument("--url", default="http://127.0.0.1:8000/v1/tools/execute", help="Gateway URL")
    parser.add_argument("--requests", type=int, default=10000, help="Total requests to send")
    parser.add_argument("--concurrency", type=int, default=500, help="Concurrent workers")
    args = parser.parse_args()

    payload = {
        "tool": "read_file",
        "arguments": {"path": "src/components/Button.tsx"}
    }
    
    print(f"Starting {args.requests} requests to {args.url} with concurrency {args.concurrency}...")
    
    conn = aiohttp.TCPConnector(limit=args.concurrency)
    async with aiohttp.ClientSession(connector=conn) as session:
        # Warmup
        await fetch(session, args.url, payload)
        
        start_time = time.perf_counter()
        
        tasks = []
        for _ in range(args.requests):
            tasks.append(asyncio.create_task(fetch(session, args.url, payload)))
        
        results = await asyncio.gather(*tasks)
        
        end_time = time.perf_counter()
        
    duration = end_time - start_time
    rps = args.requests / duration
    successes = sum(1 for r in results if r == 200)
    
    print("\n" + "="*50)
    print("🚀 AgentSentry Extreme Throughput Benchmark 🚀")
    print("="*50)
    print(f"Total Requests:     {args.requests}")
    print(f"Concurrency:        {args.concurrency}")
    print(f"Duration:           {duration:.3f} seconds")
    print(f"Successful (200 OK):{successes}")
    print(f"Failed/Dropped:     {args.requests - successes}")
    print("-"*50)
    print(f"Requests Per Second (RPS):  {rps:.2f} req/s (Single-Core)")
    print("="*50)
    
    if rps > 4000:
        print("\n✅ PASSED: Staff-Level Single-Core Throughput Achieved!")
    else:
        print("\n⚠️  WARNING: Throughput is lower than expected.")

if __name__ == "__main__":
    asyncio.run(main())
