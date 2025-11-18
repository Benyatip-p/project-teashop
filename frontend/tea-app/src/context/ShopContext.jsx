import { createContext, useContext, useState, useEffect } from "react";

const ShopContext = createContext();

export const useShop = () => useContext(ShopContext);

export const ShopProvider = ({ children }) => {
  const [cart, setCart] = useState(() => {
    const stored = localStorage.getItem("cart");
    return stored ? JSON.parse(stored) : [];
  });

  const [favorites, setFavorites] = useState(() => {
    const stored = localStorage.getItem("favorites");
    return stored ? JSON.parse(stored) : [];
  });

  // sync localStorage
  useEffect(() => {
    localStorage.setItem("cart", JSON.stringify(cart));
  }, [cart]);

  useEffect(() => {
    localStorage.setItem("favorites", JSON.stringify(favorites));
  }, [favorites]);

  // helpers
  const isFavorite = (productId) =>
    favorites.some((item) => item.id === productId);

  const isInCart = (productId) =>
    cart.some((item) => item.id === productId);

  const toggleFavorite = (product) => {
    setFavorites((prev) =>
      prev.some((item) => item.id === product.id)
        ? prev.filter((item) => item.id !== product.id)
        : [...prev, product]
    );
  };

  // ✅ ใช้ qty ที่ส่งมาจริง ๆ
  const addToCart = (product, qty = 1) => {
    const quantityToAdd = Number(qty) || 1;

    setCart((prev) => {
      const existing = prev.find((item) => item.id === product.id);
      if (existing) {
        return prev.map((item) =>
          item.id === product.id
            ? { ...item, qty: (item.qty || 1) + quantityToAdd }
            : item
        );
      }
      return [...prev, { ...product, qty: quantityToAdd }];
    });
  };

  const removeFromCart = (productId) => {
    setCart((prev) => prev.filter((item) => item.id !== productId));
  };

  const updateCartQty = (productId, newQty) => {
  const qtyNum = Number(newQty);

    setCart(prev =>
        prev
        .map(item =>
            item.id === productId
            ? { ...item, qty: qtyNum < 1 ? 1 : qtyNum } // อย่างน้อย 1
            : item
        )
    );
    };

  const cartItemCount = cart.length; // จำนวน “รายการ” ในตะกร้า

  return (
    <ShopContext.Provider
      value={{
        cart,
        favorites,
        cartCount: cartItemCount,
        toggleFavorite,
        addToCart,
        removeFromCart,
        updateCartQty,
        isFavorite,
        isInCart,
      }}
    >
      {children}
    </ShopContext.Provider>
  );
};