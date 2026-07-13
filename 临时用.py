s = input()
anss = ""
cnt = 0
for c in s:
    if c >= '0' and c <= '9':
        cnt += 1
        anss += c
    if cnt == 2 : break
if anss != "" : ans = int(anss)
if anss == "" or ans == 0 : print("not find")
else : print(ans)