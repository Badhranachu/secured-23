import { useNavigate } from 'react-router-dom';

export function BackButton({ fallbackTo = '/', className = '' }) {
  const navigate = useNavigate();

  const handleBack = () => {
    if (window.history.length > 1) {
      navigate(-1);
      return;
    }
    navigate(fallbackTo);
  };

  return (
    <button type="button" className={`back-button ${className}`.trim()} onClick={handleBack}>
      Back
    </button>
  );
}
