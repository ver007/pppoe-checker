import redis
r = redis.StrictRedis(host='localhost', port=6379, db=0)
print r.smembers('server')
print r.smembers('server:118.69.250.20')
r.sadd('server', '118.69.250.20')
mac = '00:16:3e:{0:02}:{1:02d}:{2:02d}'
user = 'Sgfdl-noctest'
user_map = {
    'Sgfdl-noctest': 1
}
for i in range(101, 401):
    cur_mac = mac.format(user_map[user], i//100, i % 100)
    r.srem('server:118.69.250.20', '{0}-{1}|noctest|eth1.201|{2}'.format(user, i, cur_mac))
for i in range(101, 401):
    cur_mac = mac.format(user_map[user], i//100, i % 100)
    r.sadd('server:118.69.250.20', '{0}-{1}|noctest|eth1|{2}'.format(user, i, cur_mac))


#r.sadd('server:118.69.250.20','Hndsl-testload-134:123456:eth0.208')

print r.smembers('server')
print r.smembers('server:118.69.250.20')
