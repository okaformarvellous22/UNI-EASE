# Uni Ease MVP

Uni Ease student services MVP with customer, worker, and admin flows.

## Run locally
Requires Node.js 22 or later.

```bash
npm start
```

Then visit http://localhost:3000.

## Demo logins
- Customer: customer@campusassist.local / customer123
- Worker: worker@campusassist.local / worker123
- Admin: admin@campusassist.local / admin123

## Deployment notes
This project is a Node.js HTTP server using `node:sqlite`. It is not a static website and should not be deployed as a static app. The host must support a long-running Node.js service and Node.js 22. SQLite storage must be on a persistent disk if order/user data must survive redeploys and restarts. The demo credentials must be changed before public use.
