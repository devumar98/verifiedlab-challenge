import React, { useEffect } from "react";
import useAuth from "../hooks/useAuth";
import useUser from "../hooks/useUser";

export default function Home() {
  const { user } = useAuth();
  const { getUser, ethBalance } = useUser();

  useEffect(() => {
    getUser();
  }, []);

  return (
    <div className="container mt-3">
      <h2>
        <div className="row">
          <div className="mb-12">
            {user?.email !== undefined ? (
              <>
                <p>Ethereum Wallet Balance: {ethBalance} ETH</p>
              </>
            ) : (
              "Please login first"
            )}
          </div>
        </div>
      </h2>
    </div>
  );
}
