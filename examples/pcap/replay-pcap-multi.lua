--- Replay pcap files on multiple interfaces.
--
-- Please note that if your storage system bandwidth does not match or
-- exceed the combined bandwidth of the interfaces you want to replay
-- packets on make sure that your pcaps fit in memory.
--
-- Also note that you will want pcaps captured on named interfaces so
-- that they contain link layer headers rather than pcaps captured on
-- "any" interface with fudged link layer headers.

local table = require "table"

local mg = require "moongen"
local device = require "device"
local memory = require "memory"
local stats = require "stats"
local log = require "log"
local pcap = require "pcap"
local limiter = require "software-ratecontrol"

function configure(parser)
   parser:option("--dev", "Device to use.")
      :args(1)
      :count("1+")
      :convert(tonumber)
      :target("devs")
   parser:argument("files", "Files to replay, must be supplied"
                      .. " as many times as --dev.")
      :args("1+")
   parser:option("-r --rate-multiplier",
                 "Speed up or slow down replay,"
                    .. " 1 = use intervals from files,"
                    .. " default = replay as fast as possible.")
      :default(0)
      :convert(tonumber)
      :target("rateMultiplier")
   parser:option("-s --buffer-flush-time",
                 "Time to wait before stopping Moongen after enqueuing"
                    .. " all packets. Increase for pcaps with a very low"
                    .. " rate.")
      :default(10)
      :convert(tonumber)
      :target("bufferFlushTime")
   parser:flag("-l --loop", "Repeat pcap files until interrupted.")
   parser:option("-i --iterations",
                 "Send pcap files this number of times")
      :default(1)
      :convert(tonumber)
   parser:flag("-f --fudge-high-port",
               "Increment higher port (src or dst) in tcp/ip packets on"
                  .. " repeated transmissions")
      :default(1)
      :convert(tonumber)
      :target("fudgehighport")
   local args = parser:parse()
   return args
end

function master(args)
   local devs = {}
   for ii, dev in ipairs(args.devs) do
      table.insert(devs, device.config({port = dev}))
   end
   device.waitForLinks()
   local rateLimiters = {}
   if args.rateMultiplier > 0 then
      for ii, dev in ipairs(devs) do
         table.insert(rateLimiters, limiter:new(dev:getTxQueue(0), "custom"))
      end
   end
   local replayers = {}
   for ii, dev in ipairs(devs) do
      table.insert(replayers,
                   mg.startTask("replay",
                                dev:getTxQueue(0),
                                args.files[ii],
                                args.loop,
                                args.iterations,
                                args.fudgehighport,
                                rateLimiters[ii],
                                args.rateMultiplier,
                                args.bufferFlushTime))
      stats.startStatsTask{txDevices = {dev}}
   end
   for ii, replayer in ipairs(replayers) do
      replayer:wait()
   end
   mg:stop()
   mg.waitForTasks()
end

function replay(queue,
                file,
                loop,
                iterations,
                fudgehighport,
                rateLimiter,
                multiplier,
                sleepTime)
   local mempool = memory:createMemPool(4096)
   local bufs = mempool:bufArray()
   local pcapFile = pcap:newReader(file)
   local linkSpeed = queue.dev:getLinkStatus().speed
   local transmission = 0
   log:info("Replaying %s on %s", file, queue.dev)
   log:info("Link speed %s for %s", linkSpeed, queue.dev)

   while mg.running() do
      replayonce(queue, file, fudgehighport, rateLimiter, multiplier, bufs, pcapFile, linkSpeed, transmission)

      transmission = transmission + 1
      if loop then
         pcapFile:reset()
         log:info("%s exhausted, starting %d transmission on %s",
                  file, transmission + 1, queue.dev)
      elseif transmission < iterations then
         pcapFile:reset()
         log:info("%s exhausted, starting %d (of %d transmissions) on %s",
                  file, transmission + 1, iterations, queue.dev)
      else
         break
      end
   end

   log:info("Replay on %s: Enqueued all packets,"
            .. " waiting %d seconds for queues to flush",
            queue.dev,
            sleepTime)
   mg.sleepMillisIdle(sleepTime * 1000)
   pcapFile:close()
end



function replayonce(queue,
                    file,
                    fudgehighport,
                    rateLimiter,
                    multiplier,
                    bufs,
                    pcapFile,
                    linkSpeed,
                    transmission)
   local uint16max = 0xffff
   local prev = 0

   while mg.running() do
      local n = pcapFile:read(bufs)

      if n > 0 then
         if fudgehighport and transmission > 0 then
            -- Fudge higher port on retransmissions.
            for i = 1, n do
               local buf = bufs[i]
               local pkt = buf:getEthernetPacket()
               local ethtype = pkt.eth:resolveNextHeader()
               if ethtype ~= 'ip4' and ethtype ~= 'ip6' then
                  -- Only want to fudge port on ip packets.
                  break
               end
               pkt = buf:getTcpPacket(ethtype == 'ip4')
               if pkt[ethtype]:resolveNextHeader() ~= 'tcp' then
                  -- Only want to fudge port on tcp packets.
                  break
               end
               if pkt.tcp:getSrcPort() < pkt.tcp:getDstPort() then
                  pkt.tcp:setDstPort((pkt.tcp:getDstPort() + transmission)
                        % uint16max)
               elseif pkt.tcp:getDstPort() < pkt.tcp:getSrcPort() then
                  pkt.tcp:setSrcPort((pkt.tcp:getSrcPort() + transmission)
                        % uint16max)
               end
               buf:offloadTcpChecksum()
            end
         end

         if rateLimiter ~= nil then
            if prev == 0 then
               prev = bufs.array[0].udata64
            end
            for i = 1, n do
               local buf = bufs[i]
               -- ts is in microseconds
               local ts = buf.udata64
               if prev > ts then
                  ts = prev
               end
               local delay = ts - prev
               delay = tonumber(delay * 10^3) / multiplier -- nanoseconds
               delay = delay / (8000 / linkSpeed) -- delay in bytes
               buf:setDelay(delay)
               prev = ts
            end
         end
      else
         break
      end
      if rateLimiter then
         rateLimiter:sendN(bufs, n)
      else
         queue:sendN(bufs, n)
      end
   end
end
