import React, { useState } from 'react'
import { SearchIcon } from '@heroicons/react/outline'

const SearchBar = ({ onSearch, placeholder = 'ค้นหา...' }) => {
  const [searchTerm, setSearchTerm] = useState('')

  const handleSubmit = e => {
    e.preventDefault()
    if (!onSearch) return
    const q = searchTerm.trim()
    if (!q) return
    onSearch(q)
  }

  return (
    <form onSubmit={handleSubmit} className="relative">
      <div className="relative">
        <input
          type="text"
          value={searchTerm}
          onChange={e => setSearchTerm(e.target.value)}
          placeholder={placeholder}
          className="w-full rounded-lg border border-gray-300 py-3 pl-10 pr-4 text-sm text-gray-800 placeholder-gray-400 transition-all duration-200 focus:outline-none focus:border-transparent focus:ring-2 focus:ring-viridian-500"
        />
        <SearchIcon className="pointer-events-none absolute left-3 top-1/2 h-5 w-5 -translate-y-1/2 text-gray-400" />
        <button
          type="submit"
          className="absolute right-2 top-1/2 -translate-y-1/2 rounded-md bg-viridian-600 px-4 py-1.5 text-sm font-medium text-white transition-colors duration-200 hover:bg-viridian-700"
        >
          ค้นหา
        </button>
      </div>
    </form>
  )
}

export default SearchBar
