import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';

import { useAuth } from '../../app/auth';
import { BackButton } from '../../components/common/BackButton';

export function LoginPage() {
  const auth = useAuth();
  const navigate = useNavigate();
  const [form, setForm] = useState({ email: '', password: '' });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (event) => {
    event.preventDefault();
    setLoading(true);
    setError('');
    try {
      const data = await auth.login(form);
      navigate(data.user.role === 'admin' ? '/admin/dashboard' : '/dashboard');
    } catch (requestError) {
      setError(requestError.response?.data?.detail || 'Unable to sign in.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-page">
      <form className="auth-card" onSubmit={handleSubmit}>
        <BackButton fallbackTo="/" className="auth-back-button" />
        <div className="eyebrow">AEGIS AI</div>
        <h1>Welcome back</h1>
        <p>Sign in to your local security workspace.</p>
        {error ? <div className="alert error">{error}</div> : null}
        <label className="field"><span>Email</span><input value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} /></label>
        <label className="field"><span>Password</span><input type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} /></label>
        <button className="primary-button" type="submit" disabled={loading}>{loading ? 'Signing in...' : 'Sign In'}</button>
        <div className="auth-links"><Link to="/register">Create account</Link><Link to="/forgot-password">Forgot password</Link></div>
      </form>
    </div>
  );
}

