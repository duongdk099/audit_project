import Stripe from 'stripe';
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

export async function POST(req) {
    try {
      // TODO : Fix the issue with req.headers.origin
      const website = 'https://nutritionscore.site';
        
      const session = await stripe.checkout.sessions.create({
        payment_method_types: ['card'],
        line_items: [
          {
            price_data: {
              currency: 'eur',
              product_data: { name: 'Premium VIP Membership', description: 'Access to premium features' },
              unit_amount: 500,
            },
            quantity: 1,
          },
        ],
        mode: 'payment',
        success_url: `${website}/payment-success`,
        cancel_url: `${website}/payment-cancel`,
      });
      return new Response(JSON.stringify({ sessionId: session.id }), { status: 200 });
    } catch (error) {
      console.error("Stripe Checkout Error:", error.message);  // Add this line
      return new Response(JSON.stringify({ error: error.message }), { status: 500 });
    }
  }
  