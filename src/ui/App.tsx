import { Route, Routes } from 'react-router-dom';
import Hello from './Hello';

export default function App() {
  return (
    <Routes>
      <Route path="*" element={<Hello />} />
    </Routes>
  );
}
