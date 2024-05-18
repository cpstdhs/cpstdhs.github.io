v11 = 22
v12 = 1
v13 = 22
v14 = 1

v12 += v14
v15 = v14 + v12
v14 += v12
v13-=1

while v13:
    v12 += v14
    v15 = v14 + v12
    v14 += v12
    v13 -= 1

print(v15)

cnt = 1
v7 = 1

v7 += cnt
v17 = cnt + v7
cnt += v7
v11 -= 1

while v11:
    v7 += cnt
    v17 = cnt + v7
    cnt += v7
    v11 -= 1

print(v17)