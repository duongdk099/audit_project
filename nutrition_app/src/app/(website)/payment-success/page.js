'use client';
import { useEffect, useState } from 'react';
import Cookies from 'js-cookie';
import { createUserRole, getRolesByUserId } from '@/services/user_roles';

const VIP_ROLE_ID = 2; // Replace with your actual VIP role ID

async function assignVIPRole(userId) {
    try {
        await createUserRole(userId, VIP_ROLE_ID);
    } catch (error) {
        console.error('Failed to assign VIP role:', error);
    }
}

export default function PaymentSuccessPage() {
    const [userName, setUserName] = useState("");
    const [userRole, setUserRole] = useState("Loading role...");

    useEffect(() => {
        const authToken = Cookies.get('authToken');
        if (!authToken) {
            console.error("No authToken found. Please log in first.");
            return;
        }

        const { user_id: userId, username } = JSON.parse(authToken);
        
        setUserName(username);

        // Fetch or assign the VIP role
        getRolesByUserId(userId).then((role) => {
            if (role?.id === VIP_ROLE_ID) {
                setUserRole("VIP");
            } else {
                assignVIPRole(userId).then(() => setUserRole("VIP"));
            }
        }).catch((error) => {
            console.error("Failed to fetch user role:", error);
            setUserRole("Unknown Role");

        });
    }, []);

    return (
        <div style={{ 
            display: 'flex', 
            flexDirection: 'column', 
            alignItems: 'center', 
            justifyContent: 'center', 
            height: '100vh', 
            fontFamily: 'Arial, sans-serif',
            textAlign: 'center',
            backgroundColor: '#f9f9f9'
        }}>
            <div style={{
                backgroundColor: '#fff',
                padding: '2rem',
                borderRadius: '10px',
                boxShadow: '0 4px 12px rgba(0, 0, 0, 0.1)',
                maxWidth: '400px',
                width: '90%',
            }}>
                <h2 style={{ color: '#4CAF50', marginBottom: '1rem' }}>🎉 Payment Successful! 🎉</h2>
                <p style={{ fontSize: '1.1rem', color: '#333', marginBottom: '0.5rem' }}>
                    Thank you for your payment, <strong>{userName}</strong>!
                </p>
                <p style={{ fontSize: '1rem', color: '#666' }}>
                    You are now a valued <span style={{ fontWeight: 'bold', color: '#FF5722' }}>{userRole}</span>.
                </p>
                <div style={{ marginTop: '1.5rem', padding: '1rem' }}>
                    <p style={{ fontSize: '0.9rem', color: '#777' }}>Enjoy your VIP benefits!</p>
                </div>
            </div>
        </div>
    );
}
