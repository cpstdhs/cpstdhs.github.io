# 🐽 crypto
> 참고할만한 crypto 팁들을 기록

# Catalog
- [🐽 crypto](#-crypto)
- [Catalog](#catalog)
  - [Number Theory](#number-theory)
    - [Euclidean Algorithm](#euclidean-algorithm)
    - [Extented Euclidean Algorithm](#extented-euclidean-algorithm)
    - [Modular Inverse](#modular-inverse)
    - [Fermat's Little Theorem](#fermats-little-theorem)
    - [Quadratic Residue](#quadratic-residue)
    - [Legendre Symbol](#legendre-symbol)

## Number Theory
### Euclidean Algorithm
```py
# a mod b = bq + r
# gcd(a, b) == gcd(b, r)
# if a > b && a, b is positive
def gcd(a, b):
    return gcd(b, a % b) if b else a
```

### Extented Euclidean Algorithm
$$x_0 = 1, y_0 = 0, x_1 = 0, y_1 = 1$$
$$x_n = x_{n-2} - q_n * x_{n-1}$$
$$y_n = y_{n-2} - q_n * y_{n-1}$$
```py
# Find x, y
# ax + by = gcd(a, b) # gcd(a, b) == 1; Bezout's Identity

def egcd(a, b):
    if gcd(a, b) != 1: return;

    x0, x1 = 1, 0
    y0, y1 = 0, 1
    r0, r1 = a, b
    q = r0 // r1

    while r1:
        q = r0 // r1

        t = x0 - q * x1
        x0 = x1
        x1 = t

        t = y0 - q * y1
        y0 = y1
        y1 = t

        t = r0 % r1
        r0 = r1
        r1 = t
    
    return x0, y0
```

### Modular Inverse
$$ a\;mod\;N $$
$$ax ≡ 1\;mod\;N (a*a^{-1}\;mod\;N≡1)$$
$$ax = kN + 1$$
$$ax\;-kN=1$$
    이렇게 나온 베주 항등식에 확장 유클리드 알고리즘을 사용하면 x, 즉 a의 역함수를 구할 수 있다.

### Fermat's Little Theorem
- p is `prime`, a is `integer`
$$a^p≡a\;mod\;p$$

- p is `prime`, a and p is `coprime`
$$a^{p-1}≡1\;mod\;p$$

### Quadratic Residue
- p is `prime`, p ≠ 2, a < p
$$x^2≡a\;mod\;p$$
    a가 p의 이차잉여이다.
### Legendre Symbol && Euler's Criterion
$$(a/p) ≡ a^{(p-1)/2}\;mod\;p ≡ 1\;mod\;p(QR)≡-1\;mod\;p(NR)$$
$$QR * QR = QR$$
$$QR * NR = NR$$
$$NR * NR = QR$$
    a가 p의 이차잉여인지 판단할 수 있다.
### Tonelli-Shanks Algorithm
- find x
$$x^2≡a\;mod\;p$$
    p의 이차잉여 a에 대한 모듈러 제곱근을 구할 수 있다.

### Chinese Remainder Theorem
$$gcd(n_i,\;n_j)=1$$
$$x≡a_1\;mod\;n_1$$
$$x≡a_2\;mod\;n_2$$
$$...$$
$$x≡a_n\;mod\;n_n$$

- example
$$
\begin{cases}
x≡2\;mod\;3\\
x≡3\;mod\;5\\
x≡2\;mod\;7\\
\end{cases}
$$

$$m = 3 * 5 * 7 = 105$$
$$a_1=2, a_2=3, a_3=2$$
$$n_1 = 35, n_2 = 21, n_3 = 15$$
$$n_1*s_1 ≡ 35s_1 ≡ 2s_1 ≡ 1\;mod\;3$$
$$n_2*s_2 ≡ 21s_2 ≡ s_2 ≡ 1\;mod\;5$$
$$n_3*s_3 ≡ 15s_3 ≡ s_3 ≡ 1\;mod\;7$$
$$s_1 = 2, s_2 = 1, s_3 = 1$$
$$x ≡ (a_1*n_1*s_1 + a_2*n_2*s_2 + a_3*n_3*s_3)\;mod\;m ≡ 23\;mod\;105$$
