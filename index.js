const multicastdns = require("multicast-dns")
const mdns = multicastdns()
const { readFileSync } = require("node:fs")

const hostFileRaw = readFileSync("/hosts", "utf8")
const hosts = hostFileRaw
  .split("\n")
  .filter((line) => !line.startsWith("#"))
  .map((line) => line.split(/[  ]+/))
  .filter((group) => group.length > 1)
  .reduce(
    (hostmap, [ip, hostname]) => Object.assign(hostmap, { [hostname]: ip }),
    {}
  )
console.log("mDNS Host Router starting")
console.log("Loaded host map:")
console.log(
  Object.entries(hosts)
    .map(([hostname, ip]) => `${hostname} -> ${ip}`)
    .join("\n")
)

mdns.on("query", (query) => {
  const name = query.questions[0].name

  const ip = hosts[name]
  if (!ip) {
    console.log(`Ignoring query for "${name}"`)
    return
  }
  console.log(`Responding to query for "${name}" with IP "${ip}"`)
  mdns.respond({
    answers: [
      {
        name: name + '.',
        type: "A", // IPv4
        ttl: 300,
        data: ip
      }
    ]
  })
})

console.log("Ready!")

process.once("SIGTERM", () => {
  console.log("SIGTERM received, closing!")
  mdns.destroy()
  process.exit()
})

