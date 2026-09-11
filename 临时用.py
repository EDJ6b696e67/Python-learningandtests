n = 200
with open("test10.txt", "w", encoding="utf-8") as f:
    f.write(f"{n} {n}\n")
    for i in range(n):
        f.write(f"{i} {i+1} 1\n")