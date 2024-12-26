import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom"; // Use React Router for navigation

const Navbar = () => {
  const [email, setEmail] = useState(null);
  const navigate = useNavigate();

  useEffect(() => {
    // Retrieve email from localStorage when the component mounts
    const storedEmail = localStorage.getItem("email");
    setEmail(storedEmail); // Set the email in the state
  }, []);

  const handleSignOut = () => {
    // Remove token from localStorage to log out
    localStorage.removeItem("token");
    localStorage.removeItem("email"); // Optionally remove email as well
    // Redirect to the login page
    navigate("/login");
  };

  const handleUpload = () => {
    navigate("/upload"); // Navigate to the Upload page
  };

  const handleHome = () => {
    navigate("/dashboard"); // Navigate to the Home page
  };

  return (
    <nav className="bg-blue-600 p-4">
      <div className="flex justify-between items-center">
        <div className="text-white text-xl font-bold">
          File Management
        </div>
        <div className="flex items-center space-x-4">
        <button
            className="text-white bg-blue-500 hover:bg-blue-600 px-4 py-2 rounded-md"
          >
            Welcome, {email}
          </button>
          
          <button
            onClick={handleHome}
            className="ml-2 text-white bg-blue-500 hover:bg-blue-600 px-4 py-2 rounded-md"
          >
            Home
          </button>
          <button
            onClick={handleUpload}
            className="ml-2 text-white bg-green-500 hover:bg-green-600 px-4 py-2 rounded-md"
          >
            Upload
          </button>
          <button
            onClick={handleSignOut}
            className="ml-2 text-white bg-red-500 hover:bg-red-600 px-4 py-2 rounded-md"
          >
            Sign Out
          </button>
        </div>
      </div>
    </nav>
  );
};

export default Navbar;
