MTA tarafından iletilen her posta, daha ayrıntılı analiz için öncelikle Comodo AV'ye gönderilecektir. Şüpheli bir dosya tespit edilirse, incelenene kadar posta karantinada kalacaktır . "Güvenli" olarak kabul edilirse posta, nihai varış noktasına ulaşmak için akışa yeniden enjekte edilecektir. Peki bu nasıl olacaktır?
Temelleri 2012 yılında Xavier Mertens adlı bir Brezilya'lı kullanıcı tarafından cuckoo sandbox'ta mail analiz olarak ortaya atılmıştır. O zamanlar Xavier Mertens Cuckoo'nun mevcut sürümü (0.3.2) kullanıyordu. Orjinal makale burada: https://blog.rootshell.be/2012/06/20/cuckoomx-automating-email-attachments-scanning-with-cuckoo/
Peki biz ne yapabiliriz? Elimizde cmdscan yapabilen bir enterprise antivirus var? Ben projeyi biraz geliştirdim ve onu geleneksel antiviruslerin de tarayabilmesi için bir dizi perl betiğinden faydalandım. (cpan modules)
Öncelikle bir mx dizilimine ihtiyacınız var. Bu dizinde perl kancaları ile nasıl mime eklerini ayrıştıracağınızı bilmelisiniz.

Postfix Master dosyasında da düzenleme yapmalısınız. Tüm akışın buradan geçebilmesi için.
Görsellerde gördüğünüz üzere tüm postayı ayrıştırıp detaylı analiz yapabiliyorum. Bunları tmp 'de tuttuğum için bir 24 saatlik crontab komut yazdım 1 gün öncekileri temizliyor. Aralık size kalmış.
