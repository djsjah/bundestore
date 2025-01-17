export const Footer: React.FC = () => {
  return (
    <footer className="bg-zinc-950 border-t-2 border-t-zinc-900 text-zinc-500 p-8">
      <div className="flex flex-col gap-2">
        <h2 className="text-xl font-bold text-white">Bundestore</h2>
        <p>
          Your one-stop destination for premium football gear, jerseys, and accessories.
          <br />
          We bring the game closer to you!
        </p>
      </div>
      <div className="mt-6 text-center text-sm">
        <p>© {new Date().getFullYear()} Bundestore. All rights reserved.</p>
      </div>
    </footer>
  );
};
