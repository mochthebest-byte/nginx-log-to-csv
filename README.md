# Nginx log → CSV

Simple script to parse nginx access logs (ingress-style format) and export them to CSV.

## Input format

Expected line format (example):

162.55.33.98 - - [26/Apr/2021:21:20:17 +0000] "GET /api/... HTTP/2.0" 200 2 "https://..." "Mozilla/5.0 ..." 69 0.003 [upstream-name] [] 192.168.226.102:3000 2 0.004 200 f9f97c8e... 
