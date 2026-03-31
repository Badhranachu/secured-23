import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';

import { useAuth } from '../../app/auth';
import { BackButton } from '../../components/common/BackButton';

export function RegisterPage() {
  const auth = useAuth();
  const navigate = useNavigate();
  const [form, setForm] = useState({ name: '', email: '', password: '' });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (event) => {
    event.preventDefault();
    setLoading(true);
    setError('');
    try {
      const data = await auth.register(form);
      navigate(data.user.role === 'admin' ? '/admin/dashboard' : '/dashboard');
    } catch (requestError) {
      const details = requestError.response?.data;
      setError(typeof details === 'string' ? details : 'Unable to create account.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-page">
      <form className="auth-card" onSubmit={handleSubmit}>
        <BackButton fallbackTo="/" className="auth-back-button" />
        <div className="eyebrow">AEGIS AI</div>
        <h1>Create account</h1>
        <p>Start scanning your local SaaS projects.</p>
        {error ? <div className="alert error">{error}</div> : null}
        <label className="field"><span>Name</span><input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></label>
        <label className="field"><span>Email</span><input value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} /></label>
        <label className="field"><span>Password</span><input type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} /></label>
        <button className="primary-button" type="submit" disabled={loading}>{loading ? 'Creating...' : 'Create Account'}</button>
        <div className="auth-links"><Link to="/login">Back to login</Link></div>
      </form>
    </div>
  );
}

