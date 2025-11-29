import React from "react"

const DeleteConfirmationModal = ({ isOpen, onClose, onConfirm, product }) => {
    if (!isOpen || !product) return null

    const handleBackdropClick = e => {
        if (e.target === e.currentTarget) {
            onClose()
        }
    }

    return (
        <div
            className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
            onClick={handleBackdropClick}
        >
            <div className="w-full max-w-md rounded-2xl bg-white p-6 shadow-xl">
                <div className="mb-4">
                    <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-rose-100">
                        <svg
                            className="h-6 w-6 text-rose-600"
                            fill="none"
                            viewBox="0 0 24 24"
                            stroke="currentColor"
                        >
                            <path
                                strokeLinecap="round"
                                strokeLinejoin="round"
                                strokeWidth={2}
                                d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z"
                            />
                        </svg>
                    </div>
                    <h3 className="text-lg font-semibold text-slate-900 text-center">
                        ยืนยันการลบสินค้า
                    </h3>
                </div>

                <div className="mb-6">
                    <p className="text-sm text-slate-600 text-center mb-3">
                        คุณกำลังจะลบสินค้าต่อไปนี้:
                    </p>
                    <div className="rounded-lg bg-slate-50 p-3">
                        <div className="flex items-center gap-3">
                            <div className="h-10 w-10 overflow-hidden rounded-lg bg-slate-200">
                                <img
                                    src={product.coverImage || "/images/placeholder.jpg"}
                                    alt={product.title}
                                    className="h-full w-full object-cover"
                                />
                            </div>
                            <div>
                                <div className="text-sm font-medium text-slate-900">
                                    {product.title}
                                </div>
                                <div className="text-xs text-slate-500">
                                    {product.category}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <div className="mb-4 rounded-lg bg-amber-50 p-3">
                    <div className="flex items-start gap-2">
                        <svg
                            className="h-5 w-5 text-amber-600 mt-0.5 flex-shrink-0"
                            fill="none"
                            viewBox="0 0 24 24"
                            stroke="currentColor"
                        >
                            <path
                                strokeLinecap="round"
                                strokeLinejoin="round"
                                strokeWidth={2}
                                d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z"
                            />
                        </svg>
                        <div className="text-sm text-amber-800">
                            <strong>คำเตือน:</strong> การลบสินค้านี้จะไม่สามารถกู้คืนได้
                            และอาจส่งผลกระทบต่อคำสั่งซื้อที่มีสินค้านี้อยู่
                        </div>
                    </div>
                </div>

                <div className="flex gap-3">
                    <button
                        onClick={onClose}
                        className="flex-1 rounded-full border border-slate-200 bg-white px-4 py-2.5 text-sm font-medium text-slate-700 hover:bg-slate-50"
                    >
                        ยกเลิก
                    </button>
                    <button
                        onClick={onConfirm}
                        className="flex-1 rounded-full bg-rose-600 px-4 py-2.5 text-sm font-medium text-white hover:bg-rose-700"
                    >
                        ลบสินค้า
                    </button>
                </div>
            </div>
        </div>
    )
}

export default DeleteConfirmationModal