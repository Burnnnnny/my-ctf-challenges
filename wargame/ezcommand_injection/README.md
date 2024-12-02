### EZ_command_injection

- Category : web
- Difficulty : easy

---

### Description
ez command injection chall

---

### Backup
[https://dreamhack.io/wargame/challenges/1204](https://dreamhack.io/wargame/challenges/1204)

---

### simple Solution


```py
@app.route('/ping', methods=['GET'])
def ping():
    host = request.args.get('host', '')
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        error_msg = 'Invalid IP address'
        print(error_msg)
        return render_template('index.html', result=error_msg)

    cmd = f'ping -c 3 {addr}'
```
사용자 입력값을 `ipaddress.ip_address`함수에 담고 ping명령어에 담고 실행합니다.

command injection이 발생하지만 `ipaddress.ip_address`함수를 우회해야합니다.

해당 함수를 우회하는 법은 ipv6와 scope id를 위주로 레퍼런스와 공식문서를 보시고 몇번 시도해보시면 

command injection이 가능한것을 볼 수 있을겁니다. 
