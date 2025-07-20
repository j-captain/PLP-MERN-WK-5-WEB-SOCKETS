import { useState } from 'react';

export default function RegisterForm({ onSuccess, onCancel }) {
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    const formData = new FormData(e.target);
    const username = formData.get('username');
    const password = formData.get('password');

    try {
      const response = await fetch('http://localhost:5000/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      });

      if (!response.ok) {
        throw new Error(await response.text());
      }

      onSuccess(username);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <input
        type="text"
        name="username"
        placeholder="Username"
        className="border p-2 rounded w-full mb-2"
        required
      />
      <input
        type="password"
        name="password"
        placeholder="Password"
        className="border p-2 rounded w-full mb-4"
        required
        minLength="6"
      />
      {error && <p className="text-red-500 text-sm mb-2">{error}</p>}
      <div className="flex gap-2">
        <button
          type="submit"
          className="bg-green-500 text-white px-4 py-2 rounded flex-1 hover:bg-green-600"
          disabled={loading}
        >
          {loading ? 'Registering...' : 'Register'}
        </button>
        <button
          type="button"
          className="bg-gray-200 px-4 py-2 rounded flex-1 hover:bg-gray-300"
          onClick={onCancel}
        >
          Cancel
        </button>
      </div>
    </form>
  );
}