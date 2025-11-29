import { createContext, useContext, useState, useEffect } from "react";

const ShopContext = createContext();

export const useShop = () => useContext(ShopContext);

const buildCartItemId = (product) => {
  const baseId = product.id;
  const variantId = product.variantId ?? null;
  const variantWeight = product.variantWeight ?? product.selectedSize ?? null;
  return `${baseId}-${variantId ?? "noVar"}-${variantWeight ?? "noSize"}`;
};

export const ShopProvider = ({ children }) => {
  const [cart, setCart] = useState(() => {
    const stored = localStorage.getItem("cart");
    return stored ? JSON.parse(stored) : [];
  });

  const [favorites, setFavorites] = useState(() => {
    const stored = localStorage.getItem("favorites");
    return stored ? JSON.parse(stored) : [];
  });

  useEffect(() => {
    localStorage.setItem("cart", JSON.stringify(cart));
  }, [cart]);

  useEffect(() => {
    localStorage.setItem("favorites", JSON.stringify(favorites));
  }, [favorites]);

  const isFavorite = (productId) =>
    favorites.some((item) => item.id === productId);

  const isInCart = (productId) =>
    cart.some((item) => item.productId === productId);

  const toggleFavorite = (product) => {
    setFavorites((prev) =>
      prev.some((item) => item.id === product.id)
        ? prev.filter((item) => item.id !== product.id)
        : [...prev, product]
    );
  };

  const addToCart = (product, qty = 1) => {
    const quantityToAdd = Number(qty) || 1;
    const cartItemId = buildCartItemId(product);

    setCart((prev) => {
      const index = prev.findIndex((item) => item.id === cartItemId);
      if (index !== -1) {
        const next = [...prev];
        const currentQty = next[index].qty || 1;
        next[index] = { ...next[index], qty: currentQty + quantityToAdd };
        return next;
      }

      const variantWeight =
        product.variantWeight ?? product.selectedSize ?? null;

      return [
        ...prev,
        {
          id: cartItemId,
          productId: product.id,
          title: product.title,
          price: product.price,
          coverImage: product.coverImage || product.image,
          qty: quantityToAdd,
          variantId: product.variantId ?? null,
          variantWeight,
          selectedSize: product.selectedSize ?? null,
        },
      ];
    });
  };

  const removeFromCart = (cartItemId) => {
    setCart((prev) => prev.filter((item) => item.id !== cartItemId));
  };

  const updateCartQty = (cartItemId, newQty) => {
    const qtyNum = Number(newQty);

    setCart((prev) =>
      prev.map((item) =>
        item.id === cartItemId
          ? { ...item, qty: qtyNum < 1 ? 1 : qtyNum }
          : item
      )
    );
  };

  const cartItemCount = cart.length;

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
