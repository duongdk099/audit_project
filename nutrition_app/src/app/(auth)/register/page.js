'use client';

import React from 'react';
import CreateUser from '@/components/database_components/user/CreateUser'; // Adjust the path to the correct location

const Register = () => {
  return (
    <div>
      <h1>Register</h1>
      <CreateUser />
    </div>
  );
};

export default Register;