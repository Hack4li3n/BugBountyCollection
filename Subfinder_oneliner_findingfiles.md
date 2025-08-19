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
Below in a line:
```
𝚜𝚞𝚋𝚏𝚒𝚗𝚍𝚎𝚛 -𝚍 𝚍𝚘𝚖𝚊𝚒𝚗.𝚌𝚘𝚖 -𝚜𝚒𝚕𝚎𝚗𝚝 | \ 𝚠𝚑𝚒𝚕𝚎 𝚛𝚎𝚊𝚍 𝚑𝚘𝚜𝚝; 𝚍𝚘 \ 𝚏𝚘𝚛 𝚙𝚊𝚝𝚑 𝚒𝚗 /𝚌𝚘𝚗𝚏𝚒𝚐.𝚓𝚜 /𝚌𝚘𝚗𝚏𝚒𝚐.𝚓𝚜𝚘𝚗 /𝚊𝚙𝚙/𝚌𝚘𝚗𝚏𝚒𝚐.𝚓𝚜 /𝚜𝚎𝚝𝚝𝚒𝚗𝚐𝚜.𝚓𝚜𝚘𝚗 /𝚍𝚊𝚝𝚊𝚋𝚊𝚜𝚎.𝚓𝚜𝚘𝚗 /𝚏𝚒𝚛𝚎𝚋𝚊𝚜𝚎.𝚓𝚜𝚘𝚗 /.𝚎𝚗𝚟 /.𝚎𝚗𝚟.𝚙𝚛𝚘𝚍𝚞𝚌𝚝𝚒𝚘𝚗 /𝚊𝚙𝚒_𝚔𝚎𝚢𝚜.𝚓𝚜𝚘𝚗 /𝚌𝚛𝚎𝚍𝚎𝚗𝚝𝚒𝚊𝚕𝚜.𝚓𝚜𝚘𝚗 /𝚜𝚎𝚌𝚛𝚎𝚝𝚜.𝚓𝚜𝚘𝚗 /𝚐𝚘𝚘𝚐𝚕𝚎-𝚜𝚎𝚛𝚟𝚒𝚌𝚎𝚜.𝚓𝚜𝚘𝚗 /𝚙𝚊𝚌𝚔𝚊𝚐𝚎.𝚓𝚜𝚘𝚗 /𝚙𝚊𝚌𝚔𝚊𝚐𝚎-𝚕𝚘𝚌𝚔.𝚓𝚜𝚘𝚗 /𝚌𝚘𝚖𝚙𝚘𝚜𝚎𝚛.𝚓𝚜𝚘𝚗 /𝚙𝚘𝚖.𝚡𝚖𝚕 /𝚍𝚘𝚌𝚔𝚎𝚛-𝚌𝚘𝚖𝚙𝚘𝚜𝚎.𝚢𝚖𝚕 /𝚖𝚊𝚗𝚒𝚏𝚎𝚜𝚝.𝚓𝚜𝚘𝚗 /𝚜𝚎𝚛𝚟𝚒𝚌𝚎-𝚠𝚘𝚛𝚔𝚎𝚛.𝚓𝚜; 𝚍𝚘 \ 𝚎𝚌𝚑𝚘 "$𝚑𝚘𝚜𝚝$𝚙𝚊𝚝𝚑"; \ 𝚍𝚘𝚗𝚎; \ 𝚍𝚘𝚗𝚎 | 𝚑𝚝𝚝𝚙𝚡 -𝚖𝚌 𝟸𝟶𝟶
```
