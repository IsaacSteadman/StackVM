Can you find or design a client side rate limiting/throttling algorithm class written in TypeScript that avoids running into rate limits and meets the following requirements?

- rolling rate limit windows
- multiple rate limit windows (example: 500000 calls per 24 hours and 150 calls per 10 seconds)
- schedule calls out into the future
- schedule calls into the future even when the current schedule includes future scheduled calls
- atomically (with locking) determine whether or not a task that requires a specific number of calls can be performed before a deadline and if so executes the task and if not throws an error describing which rate limit window is preventing the execution before the deadline
