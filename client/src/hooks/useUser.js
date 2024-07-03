import { useState, useEffect } from "react";
import useAuth from "./useAuth";
import useAxiosPrivate from "./usePrivate";

export default function useUser() {
  const { isLoggedIn, setUser, setIsLoggedIn } = useAuth();
  const axiosPrivateInstance = useAxiosPrivate();
  const [ethBalance, setEthBalance] = useState(null);

  async function getUser() {
    if (!isLoggedIn) {
      return;
    }

    try {
      const { data } = await axiosPrivateInstance.get("auth/user");
      setUser(data);
      await getEthereumBalance();
    } catch (error) {
      console.log("===", error.response);
    }
  }

  async function getEthereumBalance() {
    try {
      const { data } = await axiosPrivateInstance.get("auth/ethereum-balance");
      setEthBalance(data.eth_balance);
    } catch (error) {
      console.log("=== Ethereum balance error:", error.response);
    }
  }

  return { getUser, ethBalance };
}
