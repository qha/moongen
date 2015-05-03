local dpdk		= require "dpdk"
local memory	= require "memory"
local device	= require "device"
local stats		= require "stats"
local timer		= require "timer"

local RUN_TIME = 8
local NUM_REPS = 10

local tests = {
	{ "initUdp" },
	{ "initUdp", "touchPkt" },
	{ "initUdp", { "touchPkt", "touch2ndCacheline" }, size = 68 },
	{ "initUdp", "randomSrc" },
--	{ "initUdp", "randomDst" },
	{ "initUdp", "countSrc" },
--	{ "initUdp", "countDst" },
	{ "initUdp", { "touchPkt", "randomSrc" } },
	{ "initUdp", { "randomSrc", "randomDst" } },
	{ "initUdp", { "countSrc", "countDst" } },
	{ "initUdp", nil, "offloadIP"},
	{ "initUdp", nil, "offloadUdp"},
	{ "initTcp", nil, "offloadTcp"},
	{ "initUdp", "randomMemoryWrite", arg = 2^12 }, --   4 KiB
	{ "initUdp", "randomMemoryWrite", arg = 2^16 }, --  64 KiB
	{ "initUdp", "randomMemoryWrite", arg = 2^21 }, --   2 Mib
	{ "initUdp", "randomMemoryWrite", arg = 2^28 }, -- 256 MiB
	{ "initUdp", "randomMemoryWrite", arg = 2^30 }, --   1 GiB
	-- add your own combinations you want to test here!
}

local function tblOrStringToString(tbl)
	return type(tbl) == "table" and table.concat(tbl, ",") or tostring(tbl)
end

local function getTestDesc(test)
	return ("Init: %s, Modifier: %s, Checksums: %s, Arg: %s, Size: %s"):format(
		tblOrStringToString(test[1]),
		tblOrStringToString(test[2]),
		tblOrStringToString(test[3]),
		test.arg or "nil",
		test.size or 60
	)
end

function master(freq, port1, port2)
	if not freq or not port1 or not port2 then
		return print("Usage: cpufreqGHz port1 port2")
	end
	local dev1 = device.config(port1)
	local dev2 = device.config(port2)
	local queue1 = dev1:getTxQueue(0)
	local queue2 = dev2:getTxQueue(0)
	local devs = { dev1, dev2 }
	local queues = { queue1, queue2 }
	device.waitForLinks()
	local mem = memory.allocHuge("uint32_t*", 2^30) -- 1 GiB
	for _, test in ipairs(tests) do
		if not dpdk.running() then break end
		local rates = {}
		print(getTestDesc(test))
		for i = 1, NUM_REPS do
			print("Run " .. i)
			if not dpdk.running() then break end
			dpdk.launchLua("testSlave", queues, test[1], test[2], test[3], test.size, mem, test.arg)
			local ctr = dpdk.launchLua("counterSlave", devs)
			dpdk.waitForSlaves()
			-- there is virtually no deviation within a single run (< 0.2%)
			-- but the rate varies significantly between different runs (~1-2%)
			local tp = ctr:wait()
			rates[#rates + 1] = tp
		end
		stats.addStats(rates)
		local cyclesPerPkt = freq * 10^3 / rates.avg
		local relStdDev = rates.stdDev / rates.avg
		print(getTestDesc(test))
		print("Cycles/Pkt: " .. cyclesPerPkt .. " StdDev: " .. cyclesPerPkt * relStdDev)
		print("\n")
	end
end

function counterSlave(devs)
	local ctrs = map(devs, function(dev) return stats:newDevTxCounter(dev) end)
	local runtime = timer:new(RUN_TIME - 1)
	dpdk.sleepMillisIdle(1000) -- measure the steady state
	while dpdk.running() and runtime:running() do
		for _, ctr in ipairs(ctrs) do
			ctr:update()
		end
		dpdk.sleepMillisIdle(10)
	end
	local tp, stdDev, sum = 0, 0, 0
	for _, ctr in ipairs(ctrs) do
		local mpps = ctr:getStats()
		tp = tp + mpps.avg
		stdDev = stdDev + mpps.stdDev
		sum = sum + mpps.sum
	end
	return tp, stdDev, sum
end

-- packet initializers
function initUdp(buf, len)
	buf:getUdpPacket():fill{
		pktLength = len,
		ethSrc = "01:02:03:04:05:06",
		ethDst = "10:11:12:13:14:15",
		ipSrc = "10.0.0.2",
		ipDst = "192.168.1.1",
		udpSrc = 1234,
		udpDst = 5678,
	}
end

function initTcp(buf, len)
	buf:getTcpPacket():fill{
		pktLength = len,
		ethSrc = "01:02:03:04:05:06",
		ethDst = "10:11:12:13:14:15",
		ipSrc = "10.0.0.2",
		ipDst = "192.168.1.1",
		tcpSrc = 1234,
		tcpDst = 5678,
	}
end

-- packet modifier state
-- note that this is per task, i.e. resets itself between test runs :)
local ctr1 = 0
local ctr2 = 0
local baseIP = parseIPAddress("10.0.0.1")


-- packet modifiers

function touchPkt(buf)
	buf:getUdpPacket().payload.uint8[0] = 42
end

function touch2ndCacheline(buf)
	-- payload starts at byte 42 (counting from 0)
	-- second cacheline starts at byte 68 (CRC offloading)
	buf:getUdpPacket().payload.uint8[26] = 42
end

function randomSrc(buf)
	buf:getIPPacket().ip.src:set(math.random(0, 2^32 - 1))
end

function randomDst(buf)
	buf:getIPPacket().ip.src:set(math.random(0, 2^32 - 1))
end

function countSrc(buf)
	buf:getIPPacket().ip.src:set(baseIP + ctr1)
	-- wrap-around point does not matter as incAndWrap takes a constant time without branches (see source code)
	ctr1 = incAndWrap(ctr1, 4000)
end

function countDst(buf)
	buf:getIPPacket().ip.src:set(baseIP + ctr2)
	ctr2 = incAndWrap(ctr2, 4000)
end


local testMem

-- FIXME: this doesn't work as expected
function randomMemoryRead(buf, size)
	buf:getUdpPacket().payload.uint32[0] = testMem[math.random(size / 4)]
end

function randomMemoryWrite(buf, size)
	testMem[math.random(0, size / 4 - 1)] = buf:getUdpPacket().payload.uint32[0]
end

-- checksum offloading
function offloadUdp(bufs)
	bufs:offloadUdpChecksums()
end

function offloadTcp(bufs)
	bufs:offloadTcpChecksums()
end

function offloadIP(bufs)
	bufs:offloadIPChecksums()
end

local function compose(funcs)
	local func = "return function(a1, a2) %s end"
	local calls = ""
	for i, v in ipairs(funcs) do
		if not _G[v] then
			error("function " .. v .. " does not exist")
		end
		calls = calls .. v .. "(a1, a2)\n"
	end
	return loadstring(func:format(calls))()
end

function testSlave(queues, pktInit, pktMod, checksum, size, randomAccessMem, arg)
	testMem = randomAccessMem
	local size = size or 60
	local nullFunc = function() end
	if pktInit then
		pktInit = _G[pktInit] or error("function " .. pktInit .. " does not exist")
	else 
		pktInit = nullFunc
	end
	if type(pktMod) == "table" then
		pktMod = compose(pktMod)
	elseif pktMod then
		pktMod = _G[pktMod] or error("function " .. pktMod .. " does not exist")
	else
		pktMod = nullFunc
	end
	if type(checksum) == "table" then
		pktMod = compose(checksum)
	elseif checksum then
		checksum = _G[checksum] or error("function " .. checksum .. " does not exist")
	else
		checksum = nullFunc
	end
	local mem = memory.createMemPool(function(buf)
		pktInit(buf, size, arg)
	end)
	bufs = mem:bufArray()
	local runtime = timer:new(RUN_TIME)
	while dpdk.running() and runtime:running() do
		for _, queue in ipairs(queues) do
			bufs:alloc(size)
			-- something goes horribly wrong when the loop below is empty 
			if pktMod ~= nullFunc then
				for _, buf in ipairs(bufs) do
					pktMod(buf, arg)
				end
			end
			checksum(bufs, arg)
			queue:send(bufs)
		end
	end
end

