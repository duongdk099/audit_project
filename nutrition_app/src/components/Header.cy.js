import React from 'react';
import Header from './Header';

describe('<Header />', () => {
  beforeEach(() => {
    // Mount the Header component before each test
    cy.mount(<Header />);
  });

  it('renders the header with the correct title', () => {
    // Check if the header title "NutriLife" is present
    cy.contains('h1', 'NutriLife')
      .should('exist')
      .and('have.class', 'text-2xl font-bold');
  });

  it('has navigation links for Home and Profile', () => {
    // Check if the "Home" link is present and has the correct href
    cy.get('nav').contains('a', 'Home')
      .should('have.attr', 'href', '/')
      .and('be.visible');

    // Check if the "Profile" link is present and has the correct href
    cy.get('nav').contains('a', 'Profile')
      .should('have.attr', 'href', '/profile')
      .and('be.visible');
  });

  it('has the correct background and text color', () => {
    // Verify the header has the correct classes for styling
    cy.get('header')
      .should('have.class', 'bg-green-500')
      .and('have.class', 'text-white')
      .and('have.class', 'py-4');
  });
});