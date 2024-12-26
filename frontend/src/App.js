import React from 'react';
import { BrowserRouter as Router, Route, Routes } from 'react-router-dom';
import Login from './components/Login';
import Signup from './components/Signup';
import Dashboard from './components/Dashboard'
import Upload from './components/Upload'
//import Callback from './components/Callback';  // New callback component
import PrivateRoute from './route/PrivateRoute';
function App() {
  return (
    <Router>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/signup" element={<Signup />} />
        {/*<Route path="/auth/callback" element={<Callback />} />*/}  {/* Handle the callback */}
        <Route
          path="/dashboard"
          element={
            <PrivateRoute>
              <Dashboard />
            </PrivateRoute>
          }
        />
        <Route
          path="/upload"
          element={
            <PrivateRoute>
              <Upload />
            </PrivateRoute>
          }
        />
      </Routes>
    </Router>
  );
}

export default App;
