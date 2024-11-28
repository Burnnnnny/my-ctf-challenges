### WEIRD_FILE_UPLOAD

- Category : web
- Difficulty: Medium

---

### Description

Well-known, weird, and safe file upload

---


### Backup
[https://dreamhack.io/wargame/challenges/1400](https://dreamhack.io/wargame/challenges/1400)

---

### simple Solution
랜덤이지만 고정된 파일명을 가진 파일을 업로드 할 수 있습니다.

그리고 include를 할 수 있어서 php파일을 업로드하고 파일명을 알면 RCE가 가능합니다.

그러나 RCE를 하고 싶어도 disable_functions옵션에 시스템 함수관련된 함수가 걸려있어 RCE하기 어렵습니다. 

#### exploit
엄청긴 파일명을 가진 파일을 업로드하여 에러를 유도해 파일명을 유출하고 

해당 php 버전에 관련된 disable_functions bypass PoC를 업로드하고 include해서 flag를 얻습니다. 

php 버전이 7.x 이여서 disable_functions bypass PoC가 가능합니다. 

---

### Unintended Solution
시드정하는 부분에서 php파싱과정중에 시드값이 잘려 충분히 브루트포싱이 가능합니다.

랜덤값을 에러 유발 없이 구할 수 있었던 언인텐이었고 창의적이고 충분히 난이도 있다 판단하여 워게임에서 막아두지 않았습니다.