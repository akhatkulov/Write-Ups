# Cipher's Secret Message

Room: https://tryhackme.com/room/hfb1cipherssecretmessage

Bizga shifrlash algoritmi berilgan biz bunda shifrdan chiqarish algoritmini yozib berilgan matnni shifrdan chiqarib olishimiz kerak.

Kodni tahlil qilishdan boshlaymiz. Kod qisartirib yozilgan uni avval kengaytirib olamiz.

```
def enc(plaintext):
    ciphertext = ""  # Shifrlangan matnni saqlash uchun bo'sh satr

    for i, c in enumerate(plaintext):  # Har bir belgini indeks bilan ko'rib chiqamiz
        if c.isalpha():  # Agar belgi harf bo‘lsa (A-Z yoki a-z)
            # Katta harf bo'lsa, asosiy nuqta 'A', kichik harf bo'lsa, asosiy nuqta 'a'
            if c.isupper():
                base = ord('A')
            else:
                base = ord('a')

            # Belgini joylashuv bo'yicha i martaga siljitamiz (Caesar sifrlashga o‘xshash)
            # ord(c) - base -> harfni 0-25 oraliqqa o‘tkazish
            # + i -> indeks bo‘yicha siljitish
            # % 26 -> alfavit doirasidan chiqmaslik
            # + base -> qaytadan harfga aylantirish
            shifted = (ord(c) - base + i) % 26
            new_char = chr(shifted + base)

            ciphertext += new_char
        else:
            # Agar belgi harf bo'lmasa, o'zgartirmasdan qo'shamiz (masalan: probel, nuqta, raqam)
            ciphertext += c

    return ciphertext

```

Bizda tahlil bor, bu tahlil **GPT** yordamida tavsiflangan.

Yani shifrlashga shiftga **i** qo'shilayotgan bo'lsa endi undan ayiramiz, chunki biz joyiga qaytarmoqchimiz.

Shifrdan chiqarish:

```
def dec(ciphertext):
    plaintext = ""  # Asl matnni yig'ish uchun

    for i, c in enumerate(ciphertext):  # Har bir belgi ustida indeks bilan ishlaymiz
        if c.isalpha():  # Faqat harflar (A-Z, a-z) ustida ishlaymiz
            # Harfning asosiy nuqtasi: katta harf bo‘lsa 'A', kichik bo‘lsa 'a'
            if c.isupper():
                base = ord('A')
            else:
                base = ord('a')

            # Shifrlangan belgini orqaga siljitish
            shifted = (ord(c) - base - i) % 26
            original_char = chr(shifted + base)

            plaintext += original_char
        else:
            # Agar harf bo'lmasa, o'zgartirmay qo‘shamiz
            plaintext += c

    return plaintext

```



**Natija:** a_sm4ll_crypt0_message_to_st4rt_with_THM_cracks

**Flag:** THM{a_sm4ll_crypt0_message_to_st4rt_with_THM_cracks}



### Nafas olar ekanman, to'xtamayman...