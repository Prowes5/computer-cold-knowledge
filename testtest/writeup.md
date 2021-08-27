## 逆向

### 简单

![image-20210823150810241](C:\Users\12877\AppData\Roaming\Typora\typora-user-images\image-20210823150810241.png)

可以看到会将输入字符串的十六进制形式与437261636b4d654a757374466f7246756e做比较。所以将437261636b4d654a757374466f7246756e还原成字符串就是flag。

``` 
>>> '437261636b4d654a757374466f7246756e'.decode('hex')
'CrackMeJustForFun'
```

### 中等1

![image-20210823151145188](C:\Users\12877\AppData\Roaming\Typora\typora-user-images\image-20210823151145188.png)

通过FindCrypt可以查询到可能是base64，查看main函数。

![image-20210823151253661](C:\Users\12877\AppData\Roaming\Typora\typora-user-images\image-20210823151253661.png)

直接base64解码得到flag

``` 
>>> import base64
>>> base64.b64decode('ZmxhZ3ttYWZha3VhaWxhaXFpYW5kYW9ifQ==')
'flag{mafakuailaiqiandaob}'
```

### 中等2

通过FindCrypt可以看到base64码表

![image-20210823153547266](C:\Users\12877\AppData\Roaming\Typora\typora-user-images\image-20210823153547266.png)

找到调用码表的函数

![image-20210823154139330](C:\Users\12877\AppData\Roaming\Typora\typora-user-images\image-20210823154139330.png)

交叉引用返回main函数

![image-20210823154249263](C:\Users\12877\AppData\Roaming\Typora\typora-user-images\image-20210823154249263.png)

可以看到在base64之后还有与循环变量相加的操作。之后与Str2相比较。

``` 
import base64

cipher = 'e3nifIH9b_C@n@dH'
flag = ''
for i in range(len(cipher)):
    flag += chr(ord(cipher[i])-i)

print base64.b64decode(flag)
```

### 困难

看到tea系列算法的常数

![image-20210823155557682](C:\Users\12877\AppData\Roaming\Typora\typora-user-images\image-20210823155557682.png)

可以看到符合xxtea的算法特征

![image-20210823155934062](C:\Users\12877\AppData\Roaming\Typora\typora-user-images\image-20210823155934062.png)

![image-20210823155939087](E:\桌面\安恒工作\疑似样本\0809\image-20210823155939087.png)

返回main去寻找加密的key和密文

![image-20210823160029413](C:\Users\12877\AppData\Roaming\Typora\typora-user-images\image-20210823160029413.png)

![image-20210823160046436](C:\Users\12877\AppData\Roaming\Typora\typora-user-images\image-20210823160046436.png)

``` 
#include <stdio.h>
#include <stdint.h>
#include<iostream>
#define DELTA 0x9e3779b9
#define MX (((z>>5^y<<2) + (y>>3^z<<4)) ^ ((sum^y) + (key[(p&3)^e] ^ z)))
using namespace std;

uint32_t v3[] = { 0xe74eb323, 0xb7a72836, 0x59ca6fe2, 0x967cc5c1, 0xe7802674, 
0x3d2d54e6, 0x8a9d0356,0x99dcc39c, 0x7026d8ed, 0x6a33fdad, 0xf496550a, 0x5c9c6f9e,
0x1be5d04c, 0x6723ae17, 0x5270a5c2, 0xac42130a, 
0x84be67b2, 0x705cc779, 0x5c513d98, 0xfb36da2d, 0x22179645, 0x5ce3529d, 0xd189e1fb, 
0xe85bd489, 0x73c8d11f,
0x54b5c196, 0xb67cb490, 0x2117e4ca, 0x9de3f994, 0x2f5aa1aa, 0xa7e801fd, 0xc30d6eab, 
0x1baddc9c, 0x3453b04a, 0x92a406f9, };


void btea(uint32_t* v, int n, uint32_t const key[4])
{
    uint32_t y, z, sum;
    unsigned p, rounds, e;
    if (n > 1)            /* Coding Part */
    {
        rounds = 3;
        sum = 0;
        z = v[n - 1];
        do
        {
            sum += DELTA;
            e = (sum >> 2) & 3;
            for (p = 0; p < n - 1; p++)
            {
                y = v[p + 1];
                z = v[p] += MX;
            }
            y = v[0];
            z = v[n - 1] += MX;
        } while (--rounds);
    }
    else if (n < -1)      /* Decoding Part */
    {
        n = -n;
        rounds = 6 + 52 / n;
        sum = rounds * DELTA;
        y = v[0];
        do
        {
            e = (sum >> 2) & 3;
            for (p = n - 1; p > 0; p--)
            {
                z = v[p - 1];
                y = v[p] -= MX;
            }
            z = v[n - 1];
            y = v[0] -= MX;
            sum -= DELTA;
        } while (--rounds);
    }
}



int main()
{
   
    uint32_t const k[4] = { 1,2,3,4 };
   
    int n = 35; //n的绝对值表示v的长度，取正表示加密，取负表示解密
    // v为要加密的数据是两个32位无符号整数
    // k为加密解密密钥，为4个32位无符号整数，即密钥长度为128位
    //printf("加密前原始数据：%u %u\n", v[0], v[1]);
    //btea(v, n, k);
   // printf("加密后的数据：%u %u\n", v[0], v[1]);
   btea(v3, -n, k);
   for (int i = 0; i < 35; i++)
   {
       printf("%c", v3[i]);
    }
    
    return 0;
}
```

