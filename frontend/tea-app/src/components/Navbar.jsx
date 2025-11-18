import React, { useState } from 'react';
import { useShop } from '../context/ShopContext';
import { useLocation } from 'react-router-dom';
import { Link, NavLink } from 'react-router-dom';
import { ShoppingCartIcon, SearchIcon, UserIcon, MenuIcon, XIcon, HeartIcon } from '@heroicons/react/outline';




const Navbar = () => {
     const [isMenuOpen, setIsMenuOpen] = useState(false);
     
     const { cartCount } = useShop();

     const location = useLocation();
     const isActivePath = (path) => location.pathname.startsWith(path);

     const toggleMenu = () => {
          setIsMenuOpen(!isMenuOpen);
     };

     return (
          <nav className="bg-green-900 shadow-lg sticky top-0 z-50">
               <div className="container mx-auto px-4">
                    <div className="flex justify-between items-center h-16">
                         {/* Logo */}
                         <Link to="/" className="flex items-center space-x-3 group">
                              <div className="h-10 w-10 rounded-lg flex items-center justify-center group-hover:scale-110 transition-transform">
                                   <img
                                        src="/images/logo.svg"
                                        alt="GoodTea Logo"
                                        className="h-8 w-8"
                                   />
                              </div>
                              <span className="text-2xl font-bold text-white group-hover:text-viridian-700 transition-colors">
                                   GOODTEA
                              </span>
                         </Link>

                         {/* Desktop Menu */}
                         <div className="hidden lg:flex items-center space-x-8">
                              <NavLink
                                   to="/"
                                   className={({ isActive }) =>
                                        `text-white hover:text-gray-300 transition-colors font-medium ${isActive ? 'text-gray-300 border-b-2 border-gray-300' : ''
                                        }`
                                   }
                              >
                                   หน้าแรก
                              </NavLink>
                              <NavLink
                                   to="/products"
                                   className={({ isActive }) =>
                                       `text-white hover:text-gray-300 transition-colors font-medium ${isActive ? 'text-gray-300 border-b-2 border-gray-300' : ''
                                        }`
                                   }
                              >
                                   สินค้า
                              </NavLink>
                              <NavLink
                                   to="/about"
                                   className={({ isActive }) =>
                                        `text-white hover:text-gray-300 transition-colors font-medium ${isActive ? 'text-gray-300 border-b-2 border-gray-300' : ''
                                        }`
                                   }
                              >
                                   เกี่ยวกับเรา
                              </NavLink>
                              <NavLink
                                   to="/contact"
                                   className={({ isActive }) =>
                                        `text-white hover:text-gray-300 transition-colors font-medium ${isActive ? 'text-gray-300 border-b-2 border-gray-300' : ''
                                        }`
                                   }
                              >
                                   ติดต่อ
                              </NavLink>
                         </div>

                         {/* Action Buttons */}
                         <div className="flex items-center space-x-4">
                              <button className="p-2 text-white hover:text-green-600 transition-colors">
                                   <SearchIcon className="h-6 w-6" />
                              </button>

                              <button className={`p-2 transition-colors ${isActivePath('/favorites')? 'text-green-600': 'text-white hover:text-green-400'}`}>
                                   <Link to="/favorites">
                                        <HeartIcon className="h-6 w-6" />
                                   </Link>
                              </button>

                              <button className={`relative p-2 transition-colors ${isActivePath('/cart')? 'text-green-600': 'text-white hover:text-green-400'}`}>
                                   <Link to="/cart">
                                     <ShoppingCartIcon className="h-6 w-6" />
                                   </Link>
                                   {cartCount > 0 && (
                                        <span className="absolute -top-1 -right-1 bg-red-500 text-white text-xs 
                                             rounded-full h-5 w-5 flex items-center justify-center">
                                             {cartCount}
                                        </span>
                                   )}
                              </button>

                              <button className={`p-2 transition-colors ${isActivePath('/profile')? 'text-green-600': 'text-white hover:text-green-400'}`}>
                                   <Link to="/profile">
                                     <UserIcon className="h-6 w-6" />
                                   </Link>
                              </button>

                              {/* Mobile Menu Toggle */}
                              <button
                                   className="lg:hidden p-2  text-white hover:text-white transition-colors"
                                   onClick={toggleMenu}
                              >
                                   {isMenuOpen ? (
                                        <XIcon className="h-6 w-6" />
                                   ) : (
                                        <MenuIcon className="h-6 w-6" />
                                   )}
                              </button>
                         </div>
                    </div>

                    {/* Mobile Menu */}
                    <div className={`lg:hidden transition-all duration-300 ease-in-out ${isMenuOpen ? 'max-h-64 opacity-100' : 'max-h-0 opacity-0 overflow-hidden'
                         }`}>
                         <div className="py-4 border-t">
                              <NavLink
                                   to="/"
                                   className="block py-2 text-white hover:text-white transition-colors"
                                   onClick={() => setIsMenuOpen(false)}
                              >
                                   หน้าแรก
                              </NavLink>
                              <NavLink
                                   to="/products"
                                   className="block py-2 text-white hover:text-white transition-colors"
                                   onClick={() => setIsMenuOpen(false)}
                              >
                                   สินค้า
                              </NavLink>
                              <NavLink
                                   to="/categories"
                                   className="block py-2 text-white hover:text-white transition-colors"
                                   onClick={() => setIsMenuOpen(false)}
                              >
                                   หมวดหมู่
                              </NavLink>
                              <NavLink
                                   to="/about"
                                   className="block py-2 text-white hover:text-whitetransition-colors"
                                   onClick={() => setIsMenuOpen(false)}
                              >
                                   เกี่ยวกับเรา
                              </NavLink>
                              <NavLink
                                   to="/contact"
                                   className="block py-2 text-white hover:text-white transition-colors"
                                   onClick={() => setIsMenuOpen(false)}
                              >
                                   ติดต่อ
                              </NavLink>
                         </div>
                    </div>
               </div>
          </nav>
     );
};

export default Navbar;