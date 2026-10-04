"""The add-to-cart vocabulary that marks a product page.

A page without Product structured data can still be a product page: an
add-to-cart control is the page-type signal. This table lists the common
add-to-cart and buy-now wordings in 30 languages (English first);
`PRODUCT_PAGE_TERMS` is the case-folded set of those of three characters or
more, matched as substrings of a page's visible text.
"""
from __future__ import annotations

ADD_TO_CART_TERMS: dict[str, tuple[str, ...]] = {
    "en": ("Add to Cart", "Add to Bag", "Add to Basket", "Buy Now", "Add Item"),
    "de": ("In den Warenkorb", "In den Einkaufswagen", "Kaufen", "Jetzt kaufen"),
    "fr": ("Ajouter au panier", "Acheter", "Ajouter au sac", "Acheter maintenant"),
    "es": ("Añadir al carrito", "Agregar al carrito", "Comprar", "Comprar ahora", "Añadir a la cesta"),
    "it": ("Aggiungi al carrello", "Acquista", "Compra ora", "Aggiungi alla borsa"),
    "pt": ("Adicionar ao carrinho", "Comprar", "Comprar agora", "Adicionar à sacola"),
    "nl": ("In winkelmand", "Toevoegen aan winkelwagen", "Kopen", "Nu kopen"),
    "sv": ("Lägg i varukorg", "Köp", "Köp nu", "Lägg i kundvagn"),
    "da": ("Læg i kurv", "Køb", "Køb nu", "Tilføj til kurv"),
    "no": ("Legg i handlekurv", "Kjøp", "Kjøp nå", "Legg til i kurv"),
    "fi": ("Lisää ostoskoriin", "Osta", "Osta nyt", "Lisää koriin"),
    "pl": ("Dodaj do koszyka", "Kup", "Kup teraz", "Do koszyka"),
    "cs": ("Přidat do košíku", "Koupit", "Vložit do košíku", "Koupit nyní"),
    "ro": ("Adaugă în coș", "Cumpără", "Cumpără acum", "Adaugă în coșul de cumpărături"),
    "hu": ("Kosárba", "Megveszem", "Kosárba teszem", "Vásárlás"),
    "el": ("Προσθήκη στο καλάθι", "Αγορά", "Αγοράστε τώρα"),
    "ru": ("В корзину", "Добавить в корзину", "Купить", "Купить сейчас", "Добавить"),
    "uk": ("До кошика", "Додати до кошика", "Купити", "Купити зараз"),
    "bg": ("Добави в кошницата", "Купи", "Добави в количката"),
    "zh": ("加入购物车", "立即购买", "加入购物袋", "购买", "加入篮"),
    "zh-TW": ("加入購物車", "立即購買", "加入購物袋", "購買"),
    "ja": ("カートに入れる", "購入する", "カートに追加", "今すぐ買う", "かごに入れる", "買い物かごに入れる"),
    "ko": ("장바구니", "장바구니 담기", "구매하기", "바로구매", "쇼핑백 담기", "카트에 담기"),
    "th": ("เพิ่มลงตะกร้า", "ซื้อเลย", "หยิบใส่ตะกร้า", "ซื้อสินค้า"),
    "vi": ("Thêm vào giỏ hàng", "Mua ngay", "Chọn mua", "Mua hàng"),
    "id": ("Masukkan Keranjang", "Tambah ke Keranjang", "Beli Sekarang", "Beli"),
    "ar": ("أضف إلى السلة", "اشترِ الآن", "أضف إلى العربة", "أضف للسلة"),
    "he": ("הוסף לסל", "קנה עכשיו", "הוסף לעגלה"),
    "tr": ("Sepete Ekle", "Satın Al", "Hemen Al", "Sepete At"),
    "hi": ("कार्ट में डालें", "अभी खरीदें", "खरीदें"),
}

PRODUCT_PAGE_TERMS: tuple[str, ...] = tuple(sorted(
    {term.lower() for terms in ADD_TO_CART_TERMS.values() for term in terms if len(term) >= 3}
))


def mentions_add_to_cart(text: str) -> bool:
    """True when the text contains any of `PRODUCT_PAGE_TERMS`, case-insensitively."""
    low = text.lower()
    return any(term in low for term in PRODUCT_PAGE_TERMS)
