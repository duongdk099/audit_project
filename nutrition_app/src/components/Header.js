const Header = () => {
    return (
      <header className="bg-green-500 text-white py-4">
        <div className="container mx-auto px-4">
          <h1 className="text-2xl font-bold">NutriLife</h1>
          <nav>
            <ul className="flex space-x-4">
              <li><a href="/">Home</a></li>
              <li><a href="/profile">Profile</a></li>
            </ul>
          </nav>
        </div>
      </header>
    );
  };
  
  export default Header;