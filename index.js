import express from 'express'

const app = express()

app.use(express.raw({ type: '*/*', limit: '50mb' }))

app.all('*', async (req, res) => {
   const target = req.query.url

   if (!target) {
      return res.status(400).send("Missing ?url= parameter")
   }

   const fingerprints = [
      {
         ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
         ch: '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
         platform: '"Windows"',
         mobile: "?0"
      },
      {
         ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
         ch: '"Not_A Brand";v="8", "Chromium";v="119", "Google Chrome";v="119"',
         platform: '"macOS"',
         mobile: "?0"
      },
      {
         ua: "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0",
         ch: null,
         platform: '"Linux"',
         mobile: "?0"
      },
      {
         ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
         ch: '"Not_A Brand";v="8", "Chromium";v="120", "Microsoft Edge";v="120"',
         platform: '"Windows"',
         mobile: "?0"
      }
   ]

   const profile = fingerprints[Math.floor(Math.random() * fingerprints.length)]

   const rByte = () => Math.floor(Math.random() * 255)
   const spoofIp = `${rByte()}.${rByte()}.${rByte()}.${rByte()}`

   const newHeaders = new Headers()

   newHeaders.set("User-Agent", profile.ua)
   if (profile.ch) newHeaders.set("Sec-CH-UA", profile.ch)
   newHeaders.set("Sec-CH-UA-Mobile", profile.mobile)
   newHeaders.set("Sec-CH-UA-Platform", profile.platform)

   newHeaders.set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
   newHeaders.set("Accept-Language", `en-US,en;q=0.9,id;q=${(0.7 + Math.random() * 0.2).toFixed(1)}`)
   newHeaders.set("Accept-Encoding", "gzip, deflate, br")
   newHeaders.set("Upgrade-Insecure-Requests", "1")
   newHeaders.set("Sec-Fetch-Site", "none")
   newHeaders.set("Sec-Fetch-Mode", "navigate")
   newHeaders.set("Sec-Fetch-User", "?1")
   newHeaders.set("Sec-Fetch-Dest", "document")

   newHeaders.set("X-Forwarded-For", spoofIp)
   newHeaders.set("X-Real-IP", spoofIp)
   newHeaders.set("Client-IP", spoofIp)
   newHeaders.set("True-Client-IP", spoofIp)

   const originalContentType = req.headers["content-type"]
   if (originalContentType) {
      newHeaders.set("Content-Type", originalContentType)
   }

   const hasBody = req.body && Buffer.isBuffer(req.body) && req.body.length > 0
   const body = (req.method === "GET" || req.method === "HEAD" || !hasBody) 
      ? null 
      : req.body

   try {
      const upstream = await fetch(target, {
         method: req.method,
         headers: newHeaders,
         body: body,
         redirect: "follow"
      })

      const responseHeaders = new Headers(upstream.headers)

      responseHeaders.delete("content-security-policy")
      responseHeaders.delete("x-frame-options")
      responseHeaders.delete("strict-transport-security")

      responseHeaders.set("access-control-allow-origin", "*")
      responseHeaders.set("access-control-allow-methods", "*")
      responseHeaders.set("access-control-allow-headers", "*")

      responseHeaders.forEach((value, key) => {
         res.setHeader(key, value)
      })

      res.status(upstream.status)

      const arrayBuffer = await upstream.arrayBuffer()
      const bufferResponse = Buffer.from(arrayBuffer)

      return res.send(bufferResponse)

   } catch (err) {
      return res.status(500).json({ error: err.message })
   }
})

export default app
