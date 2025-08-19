![
One liner for finding files ](https://media.licdn.com/dms/image/v2/D5622AQGgHyz6jHmEeg/feedshare-shrink_1280/B56Zi8dlmQHAAo-/0/1755508530965?e=1758758400&v=beta&t=d1w9bHn_jIrgTbG2FM3KcUHJgUJcJQN9N0XdhS5ZF20)

One liner for finding files 

```
subfinder -d domain.com -silent | \
while read host; do \
 for path in /config.js /config.json /app/config.js /settings.json /database.json /firebase.json /.env /.env.production /api_keys.json /credentials.json /secrets.json /google-services.json /package.json /package-lock.json /composer.json /pom.xml /docker-compose.yml /manifest.json /service-worker.js; do \
 echo "$host$path"; \
 done; \
done | httpx -mc 200
```
