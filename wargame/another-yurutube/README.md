### another-yurutube

- Category : web
- Difficulty : medium

---

### Description
Ivy의 [JSFull](https://dreamhack.io/wargame/challenges/1527)에 영감을 받아 만들어 봤습니다.
저도 이제 이미지를 구분할 수 있다고요!

>FLAG 형식은 SF{...}입니다. 
---

### Backup
[https://dreamhack.io/wargame/challenges/1621](https://dreamhack.io/wargame/challenges/1621)

---

### simple Solution
쿼리값에 따라 반환되는 1.jpg와 0.jpg 차이를 교차사이트에서 알고 music.youtube.com의 오픈 리다이렉션을 알면 FLAG를 얻을 수 있음

1.jpg와 0.jpg의 경우 크기가 다른 사진입니다.

교차사이트에서 이미지를 참조해서 크기를 알 수있기 때문에(CORP가 설정되어 있지 않다면) 그 점을 이용해 leak하면 됩니다.

유튜브 리다이렉션은 검색해보시면 관련 CTF문제가 존재하고 그 문제를 참고해보시면 될거 같습니다.
