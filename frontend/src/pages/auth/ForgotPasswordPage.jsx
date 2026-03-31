import { useState } from 'react';
import { Link } from 'react-router-dom';

import apiClient from '../../api/client';
import { BackButton } from '../../components/common/BackButton';

export function ForgotPasswordPage() {
  const [email, setEmail] = useState('');
  const [message, setMessage] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (event) => {
    event.preventDefault();
    setLoading(true);
    try {
      const { data } = await apiClient.post('/auth/forgot-password/', { email });
      setMessage(data.detail);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-page">
      <form className="auth-card" onSubmit={handleSubmit}>
        <BackButton fallbackTo="/" className="auth-back-button" />
        <div className="eyebrow">Password Reset Placeholder</div>
        <h1>Reset access</h1>
        <p>This backend currently returns a placeholder response while full reset flow is pending SMTP tokenization.</p>
        {message ? <div className="alert success">{message}</div> : null}
        <label className="field"><span>Email</span><input value={email} onChange={(e) => setEmail(e.target.value)} /></label>
        <button className="primary-button" type="submit" disabled={loading}>{loading ? 'Submitting...' : 'Request reset'}</button>
        <div className="auth-links"><Link to="/login">Back to login</Link></div>
      </form>
    </div>
  );
}

