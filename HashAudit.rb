#!/usr/bin/env ruby

require 'digest'
require 'optparse'
require 'time'

options = {}

OptionParser.new do |opts|
  opts.banner = "Usage: hashchecker.rb [options]"

  opts.on("-hHASH", "--hash=HASH", "Hash to crack") do |h|
    options[:hash] = h.downcase
  end

  opts.on("-fFILE", "--file=FILE", "Wordlist file") do |f|
    options[:file] = f
  end

  opts.on("-aALGO", "--algo=ALGO", "Algorithm: md5, sha1, sha256, sha512 (default md5)") do |a|
    options[:algo] = a.downcase
  end
end.parse!

if !options[:hash] || !options[:file]
  puts "Usage: ruby HashAudit.rb -h HASH -f wordlist.txt [-a ALGO]"
  exit
end

algo = options[:algo] || "md5"

hash_function = case algo
when "md5"    then ->(s){ Digest::MD5.hexdigest(s) }
when "sha1"   then ->(s){ Digest::SHA1.hexdigest(s) }
when "sha256" then ->(s){ Digest::SHA256.hexdigest(s) }
when "sha512" then ->(s){ Digest::SHA512.hexdigest(s) }
else
  puts "Unsupported algorithm: #{algo}"
  exit
end

def entropy(password)
  charset = 0
  charset += 26 if password.match?(/[a-z]/)
  charset += 26 if password.match?(/[A-Z]/)
  charset += 10 if password.match?(/[0-9]/)
  charset += 32 if password.match?(/[[:punct:]]/)
  return 0 if charset == 0
  (password.length * Math.log2(charset)).round(2)
end

puts "Algorithm: #{algo.upcase}"
puts "Target hash: #{options[:hash]}"
puts "Starting dictionary attack..."

start_time = Time.now
attempts = 0
found = false

File.foreach(options[:file]) do |line|
  password = line.strip
  attempts += 1

  if hash_function.call(password) == options[:hash]
    duration = Time.now - start_time
    puts "\n[+] Password found!"
    puts "Password: #{password}"
    puts "Attempts: #{attempts}"
    puts "Time: #{duration.round(4)} seconds"
    puts "Entropy: #{entropy(password)} bits"
    found = true
    break
  end
end

unless found
  duration = Time.now - start_time
  puts "\n[-] Password not found"
  puts "Attempts: #{attempts}"
  puts "Time: #{duration.round(4)} seconds"
end