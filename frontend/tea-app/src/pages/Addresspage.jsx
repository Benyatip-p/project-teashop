import React from 'react'
import AddressForm from '../components/AddressForm';


const Addresspage = () => {
  return (
    <div className=" min-h-screen py-6 font-sans">
      <div className="container mx-auto max-w-[1200px] px-4">
        <div className="flex flex-col md:flex-row gap-5">
          <div className="w-full md:w-3/4">
            <AddressForm />
          </div>
        </div>
      </div>
    </div>
  );
};

export default Addresspage;