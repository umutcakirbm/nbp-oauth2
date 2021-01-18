const redis = require('redis');

module.exports = ({ host, port }) => {
    const client = redis.createClient({ host, port });
    return {
        get: async (key) => {
            return new Promise((resolve, reject) => {
                client.get(key, (err, reply) => {
                    if (err) {
                        reject(err);
                    } else {
                        const redisResult = JSON.parse(reply);
                        resolve(redisResult);
                    }
                });
            });
        },
        set: (key, value) => {
            client.set(key, JSON.stringify(value));
        },
        delete: async (key) => {
            return new Promise((resolve, reject) => {
                client.del(key, (err, count) => {
                    if (err) {
                        reject(err);
                    } else {
                        resolve();
                    }
                });
            });
        }
    }
}